//! The consumer's persistent state: keys, owners, cached snapshots and policies.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use cookie_communism_proto::{BoxIdentity, Selector, SignKey, Snapshot};
use serde::{Deserialize, Serialize};

use crate::policy::{Group, Policy, Source};
use crate::{Error, Result};

/// Format 1 held age keys; format 2 holds raw X25519 keys for HPKE.
const FORMAT: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub format: u32,
    /// Consumer Ed25519 seed, base64.
    pub consumer_sign: String,
    /// Consumer X25519 private key for HPKE, base64.
    pub consumer_box: String,
    pub owners: Vec<OwnerState>,
    #[serde(default)]
    pub default_policy: Policy,
    #[serde(default)]
    pub policies: BTreeMap<Selector, Policy>,
    /// Per group domain: the owner currently supplying it.
    #[serde(default)]
    pub current: BTreeMap<String, Current>,
    /// Per group domain: owners sent a `refresh` that has not been resolved yet.
    #[serde(default)]
    pub pending_refresh: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OwnerState {
    pub grant_id: String,
    pub relay: String,
    pub owner_sign: String,
    pub owner_box: String,
    /// From the latest snapshot; the consumer's label until the first one arrives.
    pub label: String,
    pub version: u64,
    pub snapshot: Option<Snapshot>,
    /// Per group domain: the group fingerprint when the application reported it broken.
    #[serde(default)]
    pub broken: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Current {
    pub owner: String,
    pub fingerprint: String,
}

impl State {
    pub fn new() -> Self {
        Self {
            format: FORMAT,
            consumer_sign: SignKey::generate().to_b64(),
            consumer_box: BoxIdentity::generate().to_secret_string(),
            owners: Vec::new(),
            default_policy: Policy::default(),
            policies: BTreeMap::new(),
            current: BTreeMap::new(),
            pending_refresh: BTreeMap::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read(path).map_err(|e| Error::State(format!("{}: {e}", path.display())))?;
        let state: Self = serde_json::from_slice(&text)
            .map_err(|e| Error::State(format!("{}: {e}", path.display())))?;
        if state.format < FORMAT {
            return Err(Error::State(format!(
                "{}: made by an older version with incompatible keys; pair again with a new state file",
                path.display()
            )));
        }
        if state.format != FORMAT {
            return Err(Error::State(format!(
                "{}: unsupported format {}",
                path.display(),
                state.format
            )));
        }
        Ok(state)
    }

    pub fn load_or_new(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::new())
        }
    }

    /// Writes atomically (temporary file + rename) with mode 0600.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self).expect("state serialises");
        write_private_atomic(path, &json)
    }

    pub fn sign_key(&self) -> Result<SignKey> {
        SignKey::from_b64(&self.consumer_sign)
            .map_err(|e| Error::State(format!("consumer key: {e}")))
    }

    pub fn box_identity(&self) -> Result<BoxIdentity> {
        BoxIdentity::parse(&self.consumer_box)
            .map_err(|e| Error::State(format!("consumer key: {e}")))
    }

    pub fn owner_mut(&mut self, grant_id: &str) -> Option<&mut OwnerState> {
        self.owners.iter_mut().find(|o| o.grant_id == grant_id)
    }

    /// Selector groups: every approved selector across owners, grouped by domain.
    pub fn groups(&self) -> Vec<Group> {
        let mut by_domain: BTreeMap<String, BTreeSet<Selector>> = BTreeMap::new();
        for snapshot in self.owners.iter().filter_map(|o| o.snapshot.as_ref()) {
            for s in &snapshot.selectors {
                by_domain
                    .entry(s.domain.clone())
                    .or_default()
                    .insert(s.clone());
            }
        }
        by_domain
            .into_iter()
            .map(|(domain, selectors)| Group { domain, selectors })
            .collect()
    }

    pub fn group_for(&self, selector: &Selector) -> Option<Group> {
        self.groups()
            .into_iter()
            .find(|g| g.domain == selector.domain)
    }

    /// The policy for a group: the first per-selector policy among its selectors (or for its
    /// bare domain), else the default.
    pub fn policy_for(&self, group: &Group) -> &Policy {
        let domain_selector = Selector {
            domain: group.domain.clone(),
            name: None,
        };
        group
            .selectors
            .iter()
            .chain(std::iter::once(&domain_selector))
            .find_map(|s| self.policies.get(s))
            .unwrap_or(&self.default_policy)
    }

    pub fn sources(&self, group: &Group) -> Vec<Source<'_>> {
        self.owners
            .iter()
            .filter_map(|o| {
                Some(Source {
                    id: &o.grant_id,
                    label: &o.label,
                    snapshot: o.snapshot.as_ref()?,
                    broken: o.broken.get(&group.domain).map(String::as_str),
                })
            })
            .collect()
    }
}

pub(crate) fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let io = |e: std::io::Error| Error::State(format!("{}: {e}", path.display()));
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(io)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| Error::State(format!("{}: not a file path", path.display())))?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp).map_err(io)?;
    file.write_all(contents).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(io)
}
