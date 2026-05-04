use kovi::bot::runtimebot::kovi_api::{AccessControlMode, SetAccessControlList};
use kovi::RuntimeBot;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

const SELF_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AclConfig {
    #[serde(default)]
    pub plugins: HashMap<String, PluginAcl>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PluginAcl {
    #[serde(default = "default_true")]
    pub access_control: bool,
    #[serde(default = "default_whitelist")]
    pub mode: String,
    #[serde(default)]
    pub whitelist: IdList,
    #[serde(default)]
    pub blacklist: IdList,
}

fn default_true() -> bool {
    true
}

fn default_whitelist() -> String {
    "whitelist".to_string()
}

impl Default for PluginAcl {
    fn default() -> Self {
        Self {
            access_control: true,
            mode: "whitelist".to_string(),
            whitelist: IdList::default(),
            blacklist: IdList::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct IdList {
    #[serde(default)]
    pub groups: Vec<i64>,
    #[serde(default)]
    pub friends: Vec<i64>,
}

pub fn load_and_apply(bot: &RuntimeBot, data_dir: &Path) {
    let path = data_dir.join("acl.json");
    let mut config: AclConfig = match kovi::utils::load_json_data(AclConfig::default(), &path) {
        Ok(c) => c,
        Err(e) => {
            kovi::log::warn!("ACL persist: failed to load: {}", e);
            return;
        }
    };

    let all_plugins = match bot.get_plugin_info() {
        Ok(p) => p,
        Err(e) => {
            kovi::log::warn!("ACL persist: failed to read plugins: {}", e);
            return;
        }
    };

    let mut new_count = 0u32;
    for p in all_plugins.iter().filter(|p| p.name != SELF_NAME) {
        let name = &p.name;
        if config.plugins.contains_key(name) {
            continue;
        }
        let acl = PluginAcl::default();
        let _ = bot.set_plugin_access_control_mode(name, AccessControlMode::WhiteList);
        let _ = bot.set_plugin_access_control(name, true);
        config.plugins.insert(name.clone(), acl);
        new_count += 1;
    }

    for (name, acl) in &config.plugins {
        if name == SELF_NAME {
            continue;
        }
        let mode_str = if acl.mode.is_empty() {
            "whitelist"
        } else {
            match acl.mode.as_str() {
                "whitelist" | "blacklist" => &acl.mode,
                _ => "whitelist",
            }
        };
        if let Some(mode) = crate::api::string_to_mode(mode_str) {
            let _ = bot.set_plugin_access_control_mode(name, mode);
        }
        let list = match mode_str {
            "whitelist" => &acl.whitelist,
            "blacklist" => &acl.blacklist,
            _ => &acl.whitelist,
        };
        let _ = bot.set_plugin_access_control_list(
            name,
            true,
            SetAccessControlList::Changes(list.groups.clone()),
        );
        let _ = bot.set_plugin_access_control_list(
            name,
            false,
            SetAccessControlList::Changes(list.friends.clone()),
        );
        let _ = bot.set_plugin_access_control(name, acl.access_control);
    }

    if new_count > 0
        && let Err(e) = kovi::utils::save_json_data(&config, &path)
    {
        kovi::log::warn!("ACL persist: failed to save new defaults: {}", e);
    }

    kovi::log::info!(
        "ACL persist: restored {} plugins, initialized {} new with default whitelist",
        config.plugins.len() - new_count as usize,
        new_count
    );
}

/// Save current state. Stores current list into the slot matching current mode,
/// preserving the other mode's saved list from file.
pub fn save(bot: &RuntimeBot, data_dir: &Path) {
    let plugins = match bot.get_plugin_info() {
        Ok(p) => p,
        Err(e) => {
            kovi::log::warn!("ACL persist: failed to read plugins: {}", e);
            return;
        }
    };

    let path = data_dir.join("acl.json");
    let mut config: AclConfig = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    for p in plugins.iter().filter(|p| p.name != SELF_NAME) {
        let mut groups: Vec<i64> = p.access_list.groups.iter().copied().collect();
        groups.sort();
        let mut friends: Vec<i64> = p.access_list.friends.iter().copied().collect();
        friends.sort();
        let id_list = IdList { groups, friends };
        let mode = crate::api::mode_to_string(&p.list_mode);

        let entry = config.plugins.entry(p.name.clone()).or_default();
        entry.access_control = p.access_control;
        entry.mode = mode.clone();
        match mode.as_str() {
            "whitelist" => entry.whitelist = id_list,
            "blacklist" => entry.blacklist = id_list,
            _ => {}
        }
    }

    if let Err(e) = kovi::utils::save_json_data(&config, &path) {
        kovi::log::warn!("ACL persist: failed to save: {}", e);
    }
}

/// After switching mode in Kovi, load and apply the new mode's saved list from file.
pub fn apply_mode_list(bot: &RuntimeBot, name: &str, new_mode_str: &str, data_dir: &Path) {
    let path = data_dir.join("acl.json");
    let config: AclConfig = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if let Some(acl) = config.plugins.get(name) {
        let list = match new_mode_str {
            "whitelist" => &acl.whitelist,
            "blacklist" => &acl.blacklist,
            _ => return,
        };
        let _ = bot.set_plugin_access_control_list(
            name,
            true,
            SetAccessControlList::Changes(list.groups.clone()),
        );
        let _ = bot.set_plugin_access_control_list(
            name,
            false,
            SetAccessControlList::Changes(list.friends.clone()),
        );
    }
}