//! Layered policy configuration (milestone 5): builtin defaults are
//! overridden by a config file (`~/.config/iish/config.toml`, or
//! `--config`), which in turn are overridden by CLI flags. See
//! PLAN.md's "Configuration" section for the schema this mirrors.
//!
//! Not every knob is consulted by the evaluator yet: `subprocess`,
//! `run-created`, `overwrite`, `network`, `env-file-append`, and
//! per-command overrides all change behavior today (see policy.rs).
//! `elevate` is accepted here — so a config file written against
//! PLAN.md's sketch parses cleanly — but nothing consults it until the
//! sudo broker (milestone 4b) exists.

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    Allow,
    Ask,
    Deny,
}

impl Verb {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "allow" => Ok(Verb::Allow),
            "ask" => Ok(Verb::Ask),
            "deny" => Ok(Verb::Deny),
            other => Err(format!("`{other}` is not one of allow, ask, deny")),
        }
    }
}

impl<'de> Deserialize<'de> for Verb {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Verb::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    GetOnly,
    Deny,
}

impl NetworkPolicy {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "get-only" => Ok(NetworkPolicy::GetOnly),
            "deny" => Ok(NetworkPolicy::Deny),
            other => Err(format!("`{other}` is not one of get-only, deny")),
        }
    }
}

impl<'de> Deserialize<'de> for NetworkPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        NetworkPolicy::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// The live policy: builtin defaults with the file and CLI layers
/// already folded in.
#[derive(Debug, Clone)]
pub struct Config {
    pub subprocess: Verb,
    pub overwrite: Verb,
    pub env_file_append: Verb,
    pub run_created: Verb,
    pub network: NetworkPolicy,
    pub elevate: Verb,
    pub commands: HashMap<String, Verb>,
}

impl Default for Config {
    /// The built-in defaults from PLAN.md: "unlisted subprocesses ⇒
    /// ask", and everything else defaults to `ask` except network
    /// (plain GETs are unconditionally fine).
    fn default() -> Self {
        Config {
            subprocess: Verb::Ask,
            overwrite: Verb::Ask,
            env_file_append: Verb::Ask,
            run_created: Verb::Ask,
            network: NetworkPolicy::GetOnly,
            elevate: Verb::Ask,
            commands: HashMap::new(),
        }
    }
}

/// The `[defaults]` table of a config file: every field optional so a
/// user only needs to mention what they want to change.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct FileDefaults {
    subprocess: Option<Verb>,
    overwrite: Option<Verb>,
    env_file_append: Option<Verb>,
    run_created: Option<Verb>,
    network: Option<NetworkPolicy>,
    elevate: Option<Verb>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    defaults: FileDefaults,
    #[serde(default)]
    commands: HashMap<String, Verb>,
}

/// CLI-flag overrides, collected by `main`'s argument loop and applied
/// last (highest precedence).
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub subprocess: Option<Verb>,
    pub overwrite: Option<Verb>,
    pub network: Option<NetworkPolicy>,
    pub commands: HashMap<String, Verb>,
}

impl Config {
    /// `~/.config/iish/config.toml`, honoring `$XDG_CONFIG_HOME`. `None`
    /// if neither is set — nothing to look under.
    pub fn default_path() -> Option<PathBuf> {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(config_home.join("iish").join("config.toml"))
    }

    /// Build the effective policy: builtin defaults, then `path` (a
    /// missing file is not an error — most users won't have one), then
    /// `cli`.
    pub fn load(path: Option<&Path>, cli: CliOverrides) -> Result<Config, String> {
        let mut config = Config::default();
        if let Some(path) = path {
            config.merge_file(path)?;
        }
        config.merge_cli(cli);
        Ok(config)
    }

    fn merge_file(&mut self, path: &Path) -> Result<(), String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("cannot read `{}`: {e}", path.display())),
        };
        let file: File =
            toml::from_str(&text).map_err(|e| format!("cannot parse `{}`: {e}", path.display()))?;

        let d = file.defaults;
        if let Some(v) = d.subprocess {
            self.subprocess = v;
        }
        if let Some(v) = d.overwrite {
            self.overwrite = v;
        }
        if let Some(v) = d.env_file_append {
            self.env_file_append = v;
        }
        if let Some(v) = d.run_created {
            self.run_created = v;
        }
        if let Some(v) = d.network {
            self.network = v;
        }
        if let Some(v) = d.elevate {
            self.elevate = v;
        }
        self.commands.extend(file.commands);
        Ok(())
    }

    fn merge_cli(&mut self, cli: CliOverrides) {
        if let Some(v) = cli.subprocess {
            self.subprocess = v;
        }
        if let Some(v) = cli.overwrite {
            self.overwrite = v;
        }
        if let Some(v) = cli.network {
            self.network = v;
        }
        self.commands.extend(cli.commands);
    }

    /// The verdict for a per-command override, if the user has set one
    /// for exactly this name.
    pub fn command_override(&self, name: &str) -> Option<Verb> {
        self.commands.get(name).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_file(name: &str, contents: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("iish-config-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn defaults_match_plan() {
        let c = Config::default();
        assert_eq!(c.subprocess, Verb::Ask);
        assert_eq!(c.overwrite, Verb::Ask);
        assert_eq!(c.network, NetworkPolicy::GetOnly);
        assert!(c.commands.is_empty());
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let path = std::env::temp_dir().join("iish-config-does-not-exist.toml");
        let config = Config::load(Some(&path), CliOverrides::default()).unwrap();
        assert_eq!(config.subprocess, Verb::Ask);
    }

    #[test]
    fn file_overrides_only_named_fields() {
        let path = scratch_file(
            "partial",
            "[defaults]\nsubprocess = \"deny\"\n\n[commands]\nuname = \"allow\"\nsystemctl = \"deny\"\n",
        );
        let config = Config::load(Some(&path), CliOverrides::default()).unwrap();
        assert_eq!(config.subprocess, Verb::Deny);
        assert_eq!(config.overwrite, Verb::Ask); // untouched
        assert_eq!(config.command_override("uname"), Some(Verb::Allow));
        assert_eq!(config.command_override("systemctl"), Some(Verb::Deny));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn cli_overrides_win_over_file() {
        let path = scratch_file("cli-wins", "[defaults]\nsubprocess = \"deny\"\n");
        let cli = CliOverrides {
            subprocess: Some(Verb::Allow),
            ..CliOverrides::default()
        };
        let config = Config::load(Some(&path), cli).unwrap();
        assert_eq!(config.subprocess, Verb::Allow);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn unknown_field_is_a_parse_error() {
        let path = scratch_file("typo", "[defaults]\nsubprocesss = \"deny\"\n");
        assert!(Config::load(Some(&path), CliOverrides::default()).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn invalid_verb_is_a_parse_error() {
        let path = scratch_file("bad-verb", "[defaults]\nsubprocess = \"maybe\"\n");
        assert!(Config::load(Some(&path), CliOverrides::default()).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
