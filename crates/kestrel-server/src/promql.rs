//! Inject tenant and host matchers into a PromQL query.
//!
//! The client cannot choose the tenant. An existing `tenant` matcher is
//! replaced. Host scope becomes `host=~"a|b"`.

use promql_parser::parser;

pub fn inject_scope(
    promql: &str,
    tenant: &str,
    hosts: Option<&[String]>,
) -> Result<String, String> {
    if !label_ok(tenant) {
        return Err("tenant label is not allowed".to_string());
    }
    parser::parse(promql).map_err(|err| err.to_string())?;
    let mut query = strip_matcher(promql, "tenant");
    if hosts.is_some() {
        query = strip_matcher(&query, "host");
    }
    let mut extra = format!(r#"tenant="{tenant}""#);
    if let Some(hosts) = hosts {
        for host in hosts {
            if !label_ok(host) {
                return Err("host label is not allowed".to_string());
            }
        }
        let pattern = hosts
            .iter()
            .map(|host| regex_escape(host))
            .collect::<Vec<_>>()
            .join("|");
        extra.push_str(&format!(r#",host=~"{pattern}""#));
    }
    let injected = add_matchers(&query, &extra);
    parser::parse(&injected).map_err(|err| format!("{err} ({injected})"))?;
    Ok(injected)
}

fn label_ok(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':'))
}

fn regex_escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if matches!(
            ch,
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' | '|' | '^' | '$'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn strip_matcher(input: &str, name: &str) -> String {
    let pattern = format!(r#"{name}\s*(=~|!~|!=|=)\s*"(?:\\.|[^"])*"\s*,?"#);
    let regex = regex::Regex::new(&pattern).expect("matcher regex");
    let stripped = regex.replace_all(input, "").into_owned();
    stripped
        .replace(",}", "}")
        .replace("{,", "{")
        .replace(",,", ",")
        .replace("{}", "")
}

fn add_matchers(input: &str, extra: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut index = 0;
    let mut depth = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '{' && depth == 0 {
            out.push('{');
            out.push_str(extra);
            if index + 1 < chars.len() && chars[index + 1] != '}' {
                out.push(',');
            }
            depth = 1;
            index += 1;
            continue;
        }
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
        }
        if depth == 0 && is_ident_start(ch) {
            let start = index;
            index += 1;
            while index < chars.len() && is_ident_cont(chars[index]) {
                index += 1;
            }
            let name: String = chars[start..index].iter().collect();
            let mut look = index;
            while look < chars.len() && chars[look].is_whitespace() {
                look += 1;
            }
            let call = look < chars.len() && chars[look] == '(';
            let braced = look < chars.len() && chars[look] == '{';
            out.push_str(&name);
            if !call && !braced && name != "bool" {
                out.push('{');
                out.push_str(extra);
                out.push('}');
            }
            continue;
        }
        out.push(ch);
        index += 1;
    }
    out
}

fn is_ident_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_' || ch == ':'
}

fn is_ident_cont(ch: char) -> bool {
    is_ident_start(ch) || ch.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promql_injection_replaces_a_client_tenant_matcher() {
        let query = inject_scope(r#"up{tenant="other",job="api"}"#, "tenant-a", None).unwrap();
        assert!(query.contains(r#"tenant="tenant-a""#), "{query}");
        assert!(!query.contains("other"), "{query}");
        assert!(query.contains(r#"job="api""#), "{query}");
        let scoped = inject_scope(
            "up",
            "tenant-a",
            Some(&["web".to_string(), "db".to_string()]),
        )
        .unwrap();
        assert!(scoped.contains(r#"tenant="tenant-a""#), "{scoped}");
        assert!(scoped.contains("host=~"), "{scoped}");
        assert!(scoped.contains("web"), "{scoped}");
        assert!(parser::parse(&scoped).is_ok(), "{scoped}");
    }
}
