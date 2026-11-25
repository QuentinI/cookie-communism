//! The chosen cookies: as a plain list, as a Netscape `cookies.txt`, and as a reqwest cookie
//! store with a local layer for cookies sites set on the consumer's own requests.

use std::collections::BTreeSet;
use std::sync::RwLock;

use cookie_communism_proto::Cookie;
use cookie_store::{CookieStore, RawCookie};
use reqwest::header::HeaderValue;

/// The cookies currently chosen for every group.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Jar {
    pub cookies: Vec<Cookie>,
}

impl Jar {
    /// Netscape cookie file format, as read by curl, wget, yt-dlp and most cookie libraries.
    /// `HttpOnly` cookies use curl's `#HttpOnly_` prefix. Session cookies get expiry 0.
    pub fn to_netscape(&self) -> String {
        let mut out = String::from(
            "# Netscape HTTP Cookie File\n# Written by cookie-communism; do not edit.\n",
        );
        for c in &self.cookies {
            let domain = if c.host_only {
                c.host().to_string()
            } else {
                format!(".{}", c.host())
            };
            out.push_str(&format!(
                "{}{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                if c.http_only { "#HttpOnly_" } else { "" },
                domain,
                if c.host_only { "FALSE" } else { "TRUE" },
                c.path,
                if c.secure { "TRUE" } else { "FALSE" },
                c.expires.unwrap_or(0),
                c.name,
                c.value,
            ));
        }
        out
    }
}

/// A reqwest cookie store backed by the synced cookies.
///
/// Cookies set by responses go to a local layer, which takes precedence. A new snapshot
/// replaces local cookies of the same name in its group; a change of owner drops the group's
/// local cookies, since they belong to the previous owner's session.
#[derive(Default)]
pub struct SharedJar {
    layers: RwLock<Layers>,
}

#[derive(Default)]
struct Layers {
    synced: CookieStore,
    local: CookieStore,
}

impl SharedJar {
    pub(crate) fn new(jar: &Jar) -> Self {
        let shared = Self::default();
        shared.replace_synced(jar);
        shared
    }

    pub(crate) fn replace_synced(&self, jar: &Jar) {
        let mut store = CookieStore::new();
        let now = crate::now();
        for c in &jar.cookies {
            if c.is_expired(now) {
                continue;
            }
            let mut header = format!("{}={}; Path={}", c.name, c.value, c.path);
            if !c.host_only {
                header.push_str(&format!("; Domain={}", c.host()));
            }
            if let Some(exp) = c.expires {
                header.push_str(&format!("; Max-Age={}", exp - now));
            }
            if c.secure {
                header.push_str("; Secure");
            }
            if c.http_only {
                header.push_str("; HttpOnly");
            }
            let (Ok(raw), Ok(url)) = (
                RawCookie::parse(header),
                url::Url::parse(&format!("https://{}{}", c.host(), c.path)),
            ) else {
                tracing::warn!("skipping unparseable cookie {} on {}", c.name, c.domain);
                continue;
            };
            if let Err(e) = store.insert_raw(&raw, &url) {
                tracing::warn!("skipping cookie {} on {}: {e}", c.name, c.domain);
            }
        }
        self.layers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .synced = store;
    }

    /// Drops local cookies under `domain`; only those named in `names` if given.
    pub(crate) fn drop_local(&self, domain: &str, names: Option<&BTreeSet<String>>) {
        let mut layers = self.layers.write().unwrap_or_else(|e| e.into_inner());
        let doomed: Vec<(String, String, String)> = layers
            .local
            .iter_any()
            .filter_map(|c| {
                let d = c.domain.as_cow()?.to_string();
                let under = d == domain || d.ends_with(&format!(".{domain}"));
                let named = names.is_none_or(|n| n.contains(c.name()));
                (under && named).then(|| (d, c.path.to_string(), c.name().to_string()))
            })
            .collect();
        for (d, p, n) in doomed {
            layers.local.remove(&d, &p, &n);
        }
    }
}

impl reqwest::cookie::CookieStore for SharedJar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &url::Url) {
        let cookies =
            cookie_headers.filter_map(|v| RawCookie::parse(v.to_str().ok()?.to_string()).ok());
        self.layers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .local
            .store_response_cookies(cookies, url);
    }

    fn cookies(&self, url: &url::Url) -> Option<HeaderValue> {
        let layers = self.layers.read().unwrap_or_else(|e| e.into_inner());
        let mut seen = BTreeSet::new();
        let mut pairs = Vec::new();
        for (name, value) in layers
            .local
            .get_request_values(url)
            .chain(layers.synced.get_request_values(url))
        {
            if seen.insert(name.to_string()) {
                pairs.push(format!("{name}={value}"));
            }
        }
        if pairs.is_empty() {
            return None;
        }
        HeaderValue::from_str(&pairs.join("; ")).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cookie_communism_proto::SameSite;
    use reqwest::cookie::CookieStore as _;

    fn cookie(name: &str, value: &str) -> Cookie {
        Cookie {
            domain: ".example.com".into(),
            host_only: false,
            name: name.into(),
            value: value.into(),
            path: "/".into(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            expires: Some(crate::now() + 3600),
            partition_key: None,
            changed_at: 0,
        }
    }

    #[test]
    fn local_layer_overrides_and_is_dropped() {
        let jar = SharedJar::new(&Jar {
            cookies: vec![cookie("sid", "synced"), cookie("other", "o")],
        });
        let url = url::Url::parse("https://www.example.com/x").unwrap();
        let header = |j: &SharedJar| j.cookies(&url).unwrap().to_str().unwrap().to_string();
        assert!(header(&jar).contains("sid=synced"));

        let set = HeaderValue::from_static("sid=local; Path=/; Secure");
        jar.set_cookies(&mut std::iter::once(&set), &url);
        assert!(header(&jar).contains("sid=local"));
        assert!(!header(&jar).contains("sid=synced"));

        jar.drop_local("example.com", None);
        assert!(header(&jar).contains("sid=synced"));
    }

    #[test]
    fn netscape_format() {
        let mut host_only = cookie("h", "1");
        host_only.host_only = true;
        host_only.domain = "api.example.com".into();
        host_only.http_only = false;
        let text = Jar {
            cookies: vec![cookie("sid", "v"), host_only],
        }
        .to_netscape();
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with("# ")).collect();
        assert!(lines[0].starts_with("#HttpOnly_.example.com\tTRUE\t/\tTRUE\t"));
        assert!(lines[0].ends_with("\tsid\tv"));
        assert!(lines[1].starts_with("api.example.com\tFALSE\t/\tTRUE\t"));
    }
}
