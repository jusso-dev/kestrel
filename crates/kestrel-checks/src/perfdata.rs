//! Nagios perfdata: `label=value[UOM];[warn];[crit];[min];[max]`.

/// One perfdata point from a plugin line.
#[derive(Debug, Clone, PartialEq)]
pub struct PerfPoint {
    pub label: String,
    pub value: f64,
    pub uom: String,
    pub warn: Option<f64>,
    pub crit: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

const UOMS: &[&str] = &["ms", "us", "KB", "MB", "GB", "TB", "s", "B", "c", "%"];

/// Parse a perfdata string. An empty string is an empty list.
///
/// Tokens are separated by whitespace. A quoted label may contain spaces.
/// Values the parser cannot read are skipped so one bad token does not drop
/// the rest of the line.
pub fn parse_perfdata(input: &str) -> Result<Vec<PerfPoint>, PerfError> {
    let mut points = Vec::new();
    for token in split_tokens(input) {
        if token.is_empty() {
            continue;
        }
        if let Some(point) = parse_token(&token) {
            points.push(point);
        }
    }
    Ok(points)
}

fn parse_token(token: &str) -> Option<PerfPoint> {
    let (label, rest) = split_label(token)?;
    if label.is_empty() {
        return None;
    }
    let mut fields = rest.split(';');
    let (value, uom) = split_value_uom(fields.next().unwrap_or(""))?;
    Some(PerfPoint {
        label,
        value,
        uom,
        warn: fields.next().and_then(parse_number),
        crit: fields.next().and_then(parse_number),
        min: fields.next().and_then(parse_number),
        max: fields.next().and_then(parse_number),
    })
}

fn split_label(token: &str) -> Option<(String, &str)> {
    let token = token.trim();
    if let Some(rest) = token.strip_prefix('\'') {
        let mut label = String::new();
        let mut chars = rest.char_indices().peekable();
        while let Some((index, ch)) = chars.next() {
            if ch == '\'' {
                if chars.peek().is_some_and(|(_, next)| *next == '\'') {
                    chars.next();
                    label.push('\'');
                    continue;
                }
                return Some((
                    label,
                    rest[index + 1..].trim_start().strip_prefix('=')?.trim(),
                ));
            }
            label.push(ch);
        }
        return None;
    }
    if let Some(rest) = token.strip_prefix('"') {
        let end = rest.find('"')?;
        let label = rest[..end].to_string();
        let after = rest[end + 1..].trim_start();
        let rest = after.strip_prefix('=')?.trim();
        return Some((label, rest));
    }
    let (label, rest) = token.split_once('=')?;
    let label = label.trim();
    if label.is_empty() {
        return None;
    }
    Some((label.to_string(), rest.trim()))
}

fn split_value_uom(field: &str) -> Option<(f64, String)> {
    let field = field.trim();
    if field.is_empty() {
        return None;
    }
    for uom in UOMS {
        if let Some(number) = field.strip_suffix(uom) {
            if let Some(value) = parse_number(number) {
                return Some((value, (*uom).to_string()));
            }
        }
    }
    parse_number(field).map(|value| (value, String::new()))
}

fn parse_number(field: &str) -> Option<f64> {
    let field = field.trim();
    if field.is_empty() {
        return None;
    }
    let value: f64 = field.parse().ok()?;
    if value.is_finite() {
        Some(value)
    } else {
        None
    }
}

fn split_tokens(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in input.chars() {
        match quote {
            Some(mark) => {
                current.push(ch);
                if ch == mark {
                    quote = None;
                }
            }
            None if ch == '\'' || ch == '"' => {
                quote = Some(ch);
                current.push(ch);
            }
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// A perfdata string could not be read. The parser currently returns this only
/// when a caller wants a hard failure; [`parse_perfdata`] skips bad tokens.
#[derive(Debug)]
pub struct PerfError {
    message: String,
}

impl std::fmt::Display for PerfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PerfError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfdata_parses_nagios_guideline_examples() {
        let points = parse_perfdata("used=85%;90;95;0;100").unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].label, "used");
        assert_eq!(points[0].value, 85.0);
        assert_eq!(points[0].uom, "%");
        assert_eq!(points[0].warn, Some(90.0));
        assert_eq!(points[0].crit, Some(95.0));
        assert_eq!(points[0].min, Some(0.0));
        assert_eq!(points[0].max, Some(100.0));

        let points = parse_perfdata("loss=0%;80;100;0;100 rta=0.123ms;200.000;500.000;0;").unwrap();
        assert_eq!(points[0].label, "loss");
        assert_eq!(points[0].uom, "%");
        assert_eq!(points[1].label, "rta");
        assert_eq!(points[1].value, 0.123);
        assert_eq!(points[1].uom, "ms");
        assert_eq!(points[1].warn, Some(200.0));
        assert_eq!(points[1].crit, Some(500.0));
        assert_eq!(points[1].min, Some(0.0));
        assert!(points[1].max.is_none());

        let points = parse_perfdata("load1=0.240;5.000;10.000;0;").unwrap();
        assert_eq!(points[0].label, "load1");
        assert_eq!(points[0].value, 0.240);
        assert!(points[0].uom.is_empty());

        let points = parse_perfdata("'disk usage'=85%;90;95;0;100").unwrap();
        assert_eq!(points[0].label, "disk usage");
        assert_eq!(points[0].value, 85.0);
    }

    #[test]
    fn perfdata_empty_and_skips_garbage() {
        assert!(parse_perfdata("").unwrap().is_empty());
        assert!(parse_perfdata("   ").unwrap().is_empty());
        let points = parse_perfdata("not-a-point used=1;2;3;0;10").unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].label, "used");
    }

    #[test]
    fn perfdata_supports_escaped_labels_ranges_and_unknown_values() {
        let points =
            parse_perfdata("'user''s disk'=12.5GB;@10:20;~:30;0;100 unknown=U okay=-1.2e3ms")
                .unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].label, "user's disk");
        assert_eq!(points[0].value, 12.5);
        assert_eq!(points[0].uom, "GB");
        assert_eq!(points[1].value, -1200.0);
    }
}
