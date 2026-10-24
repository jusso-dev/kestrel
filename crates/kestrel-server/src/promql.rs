//! Scope every PromQL selector in the parsed syntax tree. Client host matchers
//! remain in place and intersect the server's allowed hosts.

use promql_parser::{
    label::{MatchOp, Matcher, Matchers},
    parser::{self, Expr},
};

pub fn inject_scope(
    promql: &str,
    tenant: &str,
    hosts: Option<&[String]>,
) -> Result<String, String> {
    validate_complexity(promql)?;
    if !label_ok(tenant) {
        return Err("tenant label is not allowed".to_string());
    }
    let host_matcher = hosts
        .map(|hosts| {
            if hosts.iter().any(|host| !label_ok(host)) {
                return Err("host label is not allowed".to_string());
            }
            // Dots are the only regexp metacharacters accepted by label_ok.
            // Character classes avoid a second layer of PromQL string escaping.
            let pattern = if hosts.is_empty() {
                "a^".to_string() // Cannot match any host, including a missing label.
            } else {
                format!(
                    "^({})$",
                    hosts
                        .iter()
                        .map(|host| host.replace('.', "[.]"))
                        .collect::<Vec<_>>()
                        .join("|")
                )
            };
            Ok(Matcher::new(
                MatchOp::Re(regex::Regex::new(&pattern).map_err(|error| error.to_string())?),
                "host",
                &pattern,
            ))
        })
        .transpose()?;
    let mut expression = parser::parse(promql).map_err(|error| error.to_string())?;
    scope_expr(&mut expression, tenant, host_matcher.as_ref())?;
    let scoped = expression.to_string();
    if scoped.len() > 1024 * 1024 {
        return Err("scoped PromQL query exceeds 1 MiB".to_string());
    }
    let reparsed = parser::parse(&scoped).map_err(|error| error.to_string())?;
    // This parser stores literal contents verbatim and its formatter always
    // emits double quotes. Reject any round trip that changes the syntax tree
    // (for example a backtick literal containing a quote and selector text).
    // Otherwise serialization could introduce a fresh, unscoped selector.
    if reparsed != expression {
        return Err(
            "PromQL literal cannot be safely serialized; use escaped double-quoted strings"
                .to_string(),
        );
    }
    Ok(scoped)
}

// Bound parser and recursive AST work before either receives untrusted input.
// Strings/comments do not contribute delimiter depth or expression tokens.
fn validate_complexity(query: &str) -> Result<(), String> {
    const ERROR: &str =
        "PromQL query exceeds complexity limits (16 KiB, 256 tokens, 64 nesting levels)";
    if query.len() > 16 * 1024 {
        return Err(ERROR.into());
    }
    let mut quote = None;
    let mut escaped = false;
    let mut comment = false;
    let mut depth = 0usize;
    let mut tokens = 0usize;
    let mut word = false;
    for ch in query.chars() {
        if comment {
            if ch == '\n' {
                comment = false;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' && delimiter != '`' {
                escaped = true;
            } else if ch == delimiter {
                quote = None;
            }
            continue;
        }
        if ch == '#' {
            comment = true;
            word = false;
            continue;
        }
        if ch.is_whitespace() {
            word = false;
            continue;
        }
        if matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            tokens += 1;
            word = false;
        } else {
            let next_word = ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '.');
            if !next_word || !word {
                tokens += 1;
            }
            word = next_word;
            if matches!(ch, '(' | '[' | '{') {
                depth += 1;
            }
            if matches!(ch, ')' | ']' | '}') {
                depth = depth.saturating_sub(1);
            }
        }
        if depth > 64 || tokens > 256 {
            return Err(ERROR.into());
        }
    }
    Ok(())
}

pub(crate) fn label_ok(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

fn scope_matchers(matchers: &mut Matchers, tenant: &str, host: Option<&Matcher>) {
    fn scope_branch(branch: &mut Vec<Matcher>, tenant: &str, host: Option<&Matcher>) {
        branch.retain(|matcher| matcher.name != "tenant");
        branch.push(Matcher::new(MatchOp::Equal, "tenant", tenant));
        if let Some(host) = host {
            branch.push(host.clone());
        }
        // The parser formatter sorts simple matcher lists by rendered text.
        branch.sort_by_key(ToString::to_string);
    }
    // VictoriaMetrics permits OR branches inside a selector. Every branch
    // must receive the mandatory scope; appending to only one leaks data.
    if matchers.or_matchers.is_empty() {
        scope_branch(&mut matchers.matchers, tenant, host);
    } else {
        for branch in &mut matchers.or_matchers {
            scope_branch(branch, tenant, host);
        }
    }
}

fn scope_expr(expression: &mut Expr, tenant: &str, host: Option<&Matcher>) -> Result<(), String> {
    match expression {
        Expr::VectorSelector(selector) => scope_matchers(&mut selector.matchers, tenant, host),
        Expr::MatrixSelector(selector) => scope_matchers(&mut selector.vs.matchers, tenant, host),
        Expr::Aggregate(aggregate) => {
            scope_expr(&mut aggregate.expr, tenant, host)?;
            if let Some(parameter) = &mut aggregate.param {
                scope_expr(parameter, tenant, host)?;
            }
        }
        Expr::Unary(unary) => scope_expr(&mut unary.expr, tenant, host)?,
        Expr::Binary(binary) => {
            scope_expr(&mut binary.lhs, tenant, host)?;
            scope_expr(&mut binary.rhs, tenant, host)?;
        }
        Expr::Paren(paren) => scope_expr(&mut paren.expr, tenant, host)?,
        Expr::Subquery(subquery) => scope_expr(&mut subquery.expr, tenant, host)?,
        Expr::Call(call) => {
            for argument in &mut call.args.args {
                scope_expr(argument, tenant, host)?;
            }
        }
        Expr::NumberLiteral(_) | Expr::StringLiteral(_) => {}
        Expr::Extension(_) => return Err("unsupported PromQL extension".to_string()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use promql_parser::util::{walk_expr, ExprVisitor};

    struct ScopedSelectors {
        count: usize,
    }
    impl ExprVisitor for ScopedSelectors {
        type Error = String;
        fn pre_visit(&mut self, expression: &Expr) -> Result<bool, String> {
            let selector = match expression {
                Expr::VectorSelector(selector) => selector,
                Expr::MatrixSelector(selector) => &selector.vs,
                _ => return Ok(true),
            };
            self.count += 1;
            let branches = if selector.matchers.or_matchers.is_empty() {
                vec![&selector.matchers.matchers]
            } else {
                selector.matchers.or_matchers.iter().collect()
            };
            for branch in branches {
                let tenants: Vec<_> = branch
                    .iter()
                    .filter(|matcher| matcher.name == "tenant")
                    .collect();
                assert_eq!(tenants.len(), 1);
                assert_eq!(tenants[0].value, "tenant-a");
                assert_eq!(tenants[0].op, MatchOp::Equal);
                assert!(branch.iter().any(|matcher| matcher.name == "host"
                    && matcher.is_match("web.1")
                    && !matcher.is_match("webX1")
                    && !matcher.is_match("other")));
            }
            Ok(true)
        }
    }

    #[test]
    fn scopes_every_nested_selector_without_touching_grouping_or_strings() {
        let inputs = [
            r#"sum by(host) (rate(up{tenant!="tenant-a",host="web.1"}[5m]))"#,
            r#"up{tenant="other"} / on(host) group_left(job) down"#,
            r#"topk(scalar(count(up)), sum without(job) (down))"#,
            r#"max_over_time((up + down)[1h:30s])"#,
            r#"label_replace(up, "display", "host tenant", "job", ".*")"#,
            r#"up{job="api" or tenant="other",job="db"}"#,
            r#"up offset 5m @ 1700000000"#,
        ];
        for input in inputs {
            let scoped = inject_scope(input, "tenant-a", Some(&["web.1".to_string()])).unwrap();
            let expression = parser::parse(&scoped).unwrap();
            let mut visitor = ScopedSelectors { count: 0 };
            walk_expr(&mut visitor, &expression).unwrap();
            assert!(visitor.count > 0, "{input}");
        }
    }

    #[test]
    fn requested_host_is_intersected_and_empty_scope_matches_nothing() {
        let scoped = inject_scope(
            r#"up{host="web.1"}"#,
            "tenant-a",
            Some(&["web.1".into(), "db".into()]),
        )
        .unwrap();
        assert!(scoped.contains(r#"host="web.1""#));
        let expression =
            parser::parse(&inject_scope("up", "tenant-a", Some(&[])).unwrap()).unwrap();
        let Expr::VectorSelector(selector) = expression else {
            panic!("expected selector")
        };
        let matcher = selector.matchers.find_matchers("host").pop().unwrap();
        assert!(!matcher.is_match(""));
        assert!(!matcher.is_match("web.1"));
    }

    #[test]
    fn malformed_scope_and_queries_fail_closed() {
        assert!(inject_scope("up", "bad\"tenant", None).is_err());
        assert!(inject_scope("up", "tenant-a", Some(&["bad\"host".into()])).is_err());
        assert!(inject_scope("up{", "tenant-a", None).is_err());
        assert!(inject_scope(r#"up{job=`x"} or secret{job="other`}"#, "tenant-a", None).is_err());
    }

    #[test]
    fn untrusted_queries_are_bounded_before_parsing() {
        assert!(inject_scope(
            &format!("{}up{}", "(".repeat(1000), ")".repeat(1000)),
            "tenant-a",
            None
        )
        .is_err());
        assert!(inject_scope(&format!("{}up", "-".repeat(1000)), "tenant-a", None).is_err());
        assert!(inject_scope(&"up ".repeat(6000), "tenant-a", None).is_err());
        let query = format!("up{{job=\"{}\"}} # {}", "(".repeat(1000), "(".repeat(1000));
        assert!(inject_scope(&query, "tenant-a", None).is_ok());
    }
}
