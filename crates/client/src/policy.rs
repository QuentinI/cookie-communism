//! Choosing which owner supplies the cookies for a selector group (design §4.7).

use std::collections::BTreeSet;

use cookie_communism_proto::{Cookie, Selector, Snapshot};
use serde::{Deserialize, Serialize};

/// How to choose between owners for a selector group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Policy {
    /// The source whose earliest key-cookie expiry is latest. Key cookies are the ones the
    /// group's selectors name, plus `by`. Without any, behaves like `Freshest`.
    Longest {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        by: Vec<String>,
    },
    /// The source whose cookies changed most recently.
    Freshest,
    /// Keep the current source while it is usable; then the first usable owner in `prefer`
    /// (labels or grant IDs), then `Longest`.
    Sticky {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        prefer: Vec<String>,
    },
    /// Only this owner (label or grant ID).
    Pinned { owner: String },
}

impl Default for Policy {
    fn default() -> Self {
        Policy::Longest { by: Vec::new() }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Policy::Longest { by } if by.is_empty() => f.write_str("longest"),
            Policy::Longest { by } => write!(f, "longest by {}", by.join(",")),
            Policy::Freshest => f.write_str("freshest"),
            Policy::Sticky { prefer } if prefer.is_empty() => f.write_str("sticky"),
            Policy::Sticky { prefer } => write!(f, "sticky prefer {}", prefer.join(",")),
            Policy::Pinned { owner } => write!(f, "pinned {owner}"),
        }
    }
}

/// Selectors that share a domain, and so always share an owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub domain: String,
    pub selectors: BTreeSet<Selector>,
}

impl Group {
    /// The group's cookies in a snapshot: those matching any of its selectors.
    pub fn cookies<'a>(&self, snapshot: &'a Snapshot) -> Vec<&'a Cookie> {
        snapshot
            .cookies
            .iter()
            .filter(|c| self.selectors.iter().any(|s| s.matches(c)))
            .collect()
    }

    /// Whether a snapshot's approved selectors include all of this group's.
    pub fn covered_by(&self, snapshot: &Snapshot) -> bool {
        self.selectors
            .iter()
            .all(|s| snapshot.selectors.contains(s))
    }

    /// Hash of the group's cookies, used to tell whether they changed since a failure report.
    pub fn fingerprint(&self, snapshot: &Snapshot) -> String {
        let mut parts: Vec<String> = self
            .cookies(snapshot)
            .iter()
            .map(|c| format!("{}\t{}\t{}\t{}", c.host(), c.path, c.name, c.value))
            .collect();
        parts.sort();
        cookie_communism_proto::sha256_hex(parts.join("\n").as_bytes())
    }
}

/// One owner's snapshot, as seen by the policy.
#[derive(Debug, Clone, Copy)]
pub struct Source<'a> {
    pub id: &'a str,
    pub label: &'a str,
    pub snapshot: &'a Snapshot,
    /// The group fingerprint at the time the application reported these cookies broken.
    pub broken: Option<&'a str>,
}

impl Source<'_> {
    fn is(&self, name: &str) -> bool {
        self.id == name || self.label == name
    }
}

/// Why a source cannot be used for a group, or `Ok` if it can.
pub fn usability(group: &Group, source: &Source<'_>, now: i64) -> Result<(), String> {
    if !group.covered_by(source.snapshot) {
        return Err("not approved for every selector in the group".into());
    }
    let cookies = group.cookies(source.snapshot);
    for selector in &group.selectors {
        let live = cookies
            .iter()
            .any(|c| selector.matches(c) && !c.is_expired(now));
        if !live {
            let any = cookies.iter().any(|c| selector.matches(c));
            return Err(if any {
                format!("{selector} has expired")
            } else {
                format!("browser has no cookie for {selector}")
            });
        }
    }
    if source
        .broken
        .is_some_and(|fp| fp == group.fingerprint(source.snapshot))
    {
        return Err("reported as not working, and unchanged since".into());
    }
    Ok(())
}

/// Ranks sources for `Longest` and `Freshest`; greater is better.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    /// Earliest key-cookie expiry. `None` (a session cookie, or no key cookies at all for
    /// `Freshest`) sorts below any date.
    expiry: Option<i64>,
    changed_at: i64,
    latest_expiry: Option<i64>,
}

fn rank(group: &Group, source: &Source<'_>, policy_by: Option<&[String]>) -> Rank {
    let cookies = group.cookies(source.snapshot);
    let changed_at = cookies.iter().map(|c| c.changed_at).max().unwrap_or(0);
    let latest_expiry = cookies.iter().filter_map(|c| c.expires).max();
    let expiry = policy_by.and_then(|by| {
        let keys: BTreeSet<&str> = group
            .selectors
            .iter()
            .filter_map(|s| s.name.as_deref())
            .chain(by.iter().map(String::as_str))
            .collect();
        let mut key_cookies = cookies
            .iter()
            .filter(|c| keys.contains(c.name.as_str()))
            .peekable();
        key_cookies.peek()?;
        // `Option<i64>::min` treats a session cookie (None) as the earliest.
        key_cookies.map(|c| c.expires).min()?
    });
    Rank {
        expiry,
        changed_at,
        latest_expiry,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Owner(String),
    None(String),
}

/// Picks the source for `group`. `sources` is in pairing order, which breaks ties.
pub fn choose(
    policy: &Policy,
    group: &Group,
    sources: &[Source<'_>],
    current: Option<&str>,
    now: i64,
) -> Choice {
    let usable: Vec<&Source<'_>> = sources
        .iter()
        .filter(|s| usability(group, s, now).is_ok())
        .collect();
    let current = current.and_then(|id| usable.iter().find(|s| s.id == id).copied());

    let best_by = |by: Option<&[String]>| -> Option<&Source<'_>> {
        let mut best: Option<(&Source<'_>, Rank)> = None;
        for s in &usable {
            let r = rank(group, s, by);
            if best.as_ref().is_none_or(|(_, b)| r > *b) {
                best = Some((s, r));
            }
        }
        let (best, best_rank) = best?;
        // Ties keep the current source, so equal snapshots never cause a switch.
        match current {
            Some(c) if rank(group, c, by) >= best_rank => Some(c),
            _ => Some(best),
        }
    };

    let chosen = match policy {
        Policy::Longest { by } => best_by(Some(by)),
        Policy::Freshest => best_by(None),
        Policy::Sticky { prefer } => current
            .or_else(|| {
                prefer
                    .iter()
                    .find_map(|p| usable.iter().find(|s| s.is(p)).copied())
            })
            .or_else(|| best_by(Some(&[]))),
        Policy::Pinned { owner } => {
            return match sources.iter().find(|s| s.is(owner)) {
                None => Choice::None(format!("pinned owner {owner:?} is not paired")),
                Some(s) => match usability(group, s, now) {
                    Ok(()) => Choice::Owner(s.id.to_string()),
                    Err(why) => Choice::None(format!("{}: {why}", s.label)),
                },
            };
        }
    };
    match chosen {
        Some(s) => Choice::Owner(s.id.to_string()),
        None if sources.is_empty() => Choice::None("no paired browser covers it".into()),
        None => Choice::None(
            sources
                .iter()
                .map(|s| format!("{}: {}", s.label, usability(group, s, now).unwrap_err()))
                .collect::<Vec<_>>()
                .join("; "),
        ),
    }
}

/// The owners a `refresh` message for `group` goes to.
pub fn refresh_targets(
    policy: &Policy,
    group: &Group,
    sources: &[Source<'_>],
    now: i64,
) -> Vec<String> {
    let covering = || -> Vec<String> {
        sources
            .iter()
            .filter(|s| group.covered_by(s.snapshot))
            .map(|s| s.id.to_string())
            .collect()
    };
    match policy {
        Policy::Longest { .. } | Policy::Freshest => covering(),
        Policy::Sticky { prefer } if prefer.is_empty() => covering(),
        Policy::Sticky { prefer } => {
            let ids: Vec<String> = prefer
                .iter()
                .filter_map(|p| sources.iter().find(|s| s.is(p)))
                .filter(|s| usability(group, s, now).is_err())
                .map(|s| s.id.to_string())
                .collect();
            if ids.is_empty() { covering() } else { ids }
        }
        Policy::Pinned { owner } => sources
            .iter()
            .find(|s| s.is(owner))
            .map(|s| vec![s.id.to_string()])
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cookie_communism_proto::SameSite;

    const NOW: i64 = 1_800_000_000;

    fn cookie(name: &str, expires: Option<i64>, changed_at: i64) -> Cookie {
        Cookie {
            domain: ".example.com".into(),
            host_only: false,
            name: name.into(),
            value: format!("{name}-{changed_at}"),
            path: "/".into(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            expires,
            partition_key: None,
            changed_at,
        }
    }

    fn snap(selectors: &[&str], cookies: Vec<Cookie>) -> Snapshot {
        Snapshot {
            owner_label: String::new(),
            taken_at: NOW,
            selectors: selectors.iter().map(|s| s.parse().unwrap()).collect(),
            cookies,
        }
    }

    fn group(selectors: &[&str]) -> Group {
        Group {
            domain: "example.com".into(),
            selectors: selectors.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    fn src<'a>(id: &'a str, snapshot: &'a Snapshot) -> Source<'a> {
        Source {
            id,
            label: id,
            snapshot,
            broken: None,
        }
    }

    #[test]
    fn longest_prefers_later_expiry_over_fresher_change() {
        let g = group(&["example.com:sid"]);
        // A logged in long ago with a long "remember me"; B changed recently but expires sooner.
        let a = snap(
            &["example.com:sid"],
            vec![cookie("sid", Some(NOW + 30 * 86400), NOW - 86400)],
        );
        let b = snap(
            &["example.com:sid"],
            vec![cookie("sid", Some(NOW + 3600), NOW - 60)],
        );
        let sources = [src("a", &a), src("b", &b)];
        assert_eq!(
            choose(&Policy::default(), &g, &sources, None, NOW),
            Choice::Owner("a".into())
        );
        assert_eq!(
            choose(&Policy::Freshest, &g, &sources, None, NOW),
            Choice::Owner("b".into())
        );
    }

    #[test]
    fn longest_uses_earliest_key_cookie_and_ranks_session_lowest() {
        let g = group(&["example.com:sid", "example.com:csrf"]);
        let both = ["example.com:sid", "example.com:csrf"];
        let a = snap(
            &both,
            vec![
                cookie("sid", Some(NOW + 100 * 86400), NOW),
                cookie("csrf", Some(NOW + 86400), NOW),
            ],
        );
        let b = snap(
            &both,
            vec![
                cookie("sid", Some(NOW + 10 * 86400), NOW),
                cookie("csrf", Some(NOW + 10 * 86400), NOW),
            ],
        );
        let c = snap(
            &both,
            vec![
                cookie("sid", None, NOW + 5),
                cookie("csrf", Some(NOW + 999 * 86400), NOW + 5),
            ],
        );
        let sources = [src("a", &a), src("b", &b), src("c", &c)];
        assert_eq!(
            choose(&Policy::default(), &g, &sources, None, NOW),
            Choice::Owner("b".into())
        );
    }

    #[test]
    fn domain_selector_without_by_falls_back_to_freshest() {
        let g = group(&["example.com"]);
        let a = snap(
            &["example.com"],
            vec![cookie("x", Some(NOW + 99 * 86400), NOW - 100)],
        );
        let b = snap(
            &["example.com"],
            vec![cookie("x", Some(NOW + 86400), NOW - 10)],
        );
        let sources = [src("a", &a), src("b", &b)];
        assert_eq!(
            choose(&Policy::default(), &g, &sources, None, NOW),
            Choice::Owner("b".into())
        );
        let by = Policy::Longest {
            by: vec!["x".into()],
        };
        assert_eq!(
            choose(&by, &g, &sources, None, NOW),
            Choice::Owner("a".into())
        );
    }

    #[test]
    fn ties_keep_current() {
        let g = group(&["example.com:sid"]);
        let a = snap(
            &["example.com:sid"],
            vec![cookie("sid", Some(NOW + 100), NOW)],
        );
        let b = a.clone();
        let sources = [src("a", &a), src("b", &b)];
        assert_eq!(
            choose(&Policy::default(), &g, &sources, Some("b"), NOW),
            Choice::Owner("b".into())
        );
    }

    #[test]
    fn expired_broken_and_uncovered_sources_are_skipped() {
        let g = group(&["example.com:sid"]);
        let expired = snap(
            &["example.com:sid"],
            vec![cookie("sid", Some(NOW - 1), NOW)],
        );
        let broken = snap(
            &["example.com:sid"],
            vec![cookie("sid", Some(NOW + 999), NOW)],
        );
        let narrow = snap(
            &["example.com:other"],
            vec![cookie("sid", Some(NOW + 999), NOW)],
        );
        let fp = g.fingerprint(&broken);
        let sources = [
            src("expired", &expired),
            Source {
                broken: Some(&fp),
                ..src("broken", &broken)
            },
            src("narrow", &narrow),
        ];
        let Choice::None(why) = choose(&Policy::default(), &g, &sources, None, NOW) else {
            panic!("nothing should be usable");
        };
        assert!(
            why.contains("expired") && why.contains("reported") && why.contains("approved"),
            "{why}"
        );
    }

    #[test]
    fn sticky_and_pinned() {
        let g = group(&["example.com:sid"]);
        let a = snap(
            &["example.com:sid"],
            vec![cookie("sid", Some(NOW + 10), NOW)],
        );
        let b = snap(
            &["example.com:sid"],
            vec![cookie("sid", Some(NOW + 9999), NOW)],
        );
        let dead = snap(
            &["example.com:sid"],
            vec![cookie("sid", Some(NOW - 1), NOW)],
        );
        let sources = [src("a", &a), src("b", &b), src("dead", &dead)];
        let sticky = Policy::Sticky { prefer: vec![] };
        assert_eq!(
            choose(&sticky, &g, &sources, Some("a"), NOW),
            Choice::Owner("a".into())
        );
        assert_eq!(
            choose(&sticky, &g, &sources, Some("dead"), NOW),
            Choice::Owner("b".into())
        );
        let prefer = Policy::Sticky {
            prefer: vec!["a".into()],
        };
        assert_eq!(
            choose(&prefer, &g, &sources, None, NOW),
            Choice::Owner("a".into())
        );
        let pinned = Policy::Pinned {
            owner: "dead".into(),
        };
        assert!(matches!(
            choose(&pinned, &g, &sources, Some("b"), NOW),
            Choice::None(_)
        ));
        assert_eq!(
            refresh_targets(&pinned, &g, &sources, NOW),
            vec!["dead".to_string()]
        );
        assert_eq!(
            refresh_targets(&Policy::default(), &g, &sources, NOW).len(),
            3
        );
    }
}
