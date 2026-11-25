//! Cookie selectors: `domain` or `domain:name`.

use serde::{Deserialize, Serialize};

use crate::{Cookie, Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Selector {
    /// Lowercase, without a leading dot.
    pub domain: String,
    /// `None` selects every cookie on the domain.
    pub name: Option<String>,
}

impl Selector {
    pub fn parse(text: &str) -> Result<Self> {
        let (domain, name) = match text.split_once(':') {
            Some((d, n)) => (d, Some(n)),
            None => (text, None),
        };
        let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
        let valid_domain = !domain.is_empty()
            && domain.contains('.')
            && domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
        if !valid_domain {
            return Err(Error::Encoding(format!(
                "invalid selector domain in {text:?}"
            )));
        }
        let name = match name {
            Some(n)
                if n.is_empty()
                    || n.contains(|c: char| c.is_whitespace() || c == ';' || c == '=') =>
            {
                return Err(Error::Encoding(format!("invalid cookie name in {text:?}")));
            }
            other => other.map(str::to_string),
        };
        Ok(Self { domain, name })
    }

    /// Whether a cookie on `cookie_domain` (with or without a leading dot) falls under this
    /// selector's domain: the domain itself or any subdomain.
    pub fn covers_domain(&self, cookie_domain: &str) -> bool {
        let d = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
        d == self.domain || d.ends_with(&format!(".{}", self.domain))
    }

    pub fn matches(&self, cookie: &Cookie) -> bool {
        self.covers_domain(&cookie.domain) && self.name.as_deref().is_none_or(|n| n == cookie.name)
    }
}

impl std::fmt::Display for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(n) => write!(f, "{}:{n}", self.domain),
            None => f.write_str(&self.domain),
        }
    }
}

impl std::str::FromStr for Selector {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Selector {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}

impl From<Selector> for String {
    fn from(s: Selector) -> String {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_match() {
        let s = Selector::parse(".Example.com:sid").unwrap();
        assert_eq!(s.to_string(), "example.com:sid");
        assert!(s.covers_domain(".example.com"));
        assert!(s.covers_domain("www.example.com"));
        assert!(!s.covers_domain("badexample.com"));
        assert!(Selector::parse("localhost").is_err());
        assert!(Selector::parse("example.com:").is_err());
        assert_eq!(Selector::parse("example.com").unwrap().name, None);
    }
}
