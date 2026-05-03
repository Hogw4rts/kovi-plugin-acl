use kovi::bot::runtimebot::kovi_api::{AccessControlMode, SetAccessControlList};
use kovi::MsgEvent;
use kovi::RuntimeBot;
use std::path::Path;

const SELF_NAME: &str = env!("CARGO_PKG_NAME");

fn is_whitelist(mode: &AccessControlMode) -> bool {
    matches!(mode, AccessControlMode::WhiteList)
}

pub fn list(bot: &RuntimeBot, event: &MsgEvent) {
    match bot.get_plugin_info() {
        Ok(plugins) => {
            if plugins.is_empty() {
                event.reply("没有已加载的插件。");
                return;
            }
            let mut lines: Vec<String> = vec!["插件列表:".to_string()];
            for p in &plugins {
                if p.name == SELF_NAME {
                    continue;
                }
                let status = if p.enabled { "[ON]" } else { "[OFF]" };
                let acl = if p.access_control {
                    let mode_str = if is_whitelist(&p.list_mode) {
                        "白名单"
                    } else {
                        "黑名单"
                    };
                    format!("[ACL:{}]", mode_str)
                } else {
                    "[ACL:OFF]".to_string()
                };
                lines.push(format!("  {} {} {} {}", status, p.name, p.version, acl));
            }
            event.reply(lines.join("\n"));
        }
        Err(e) => event.reply(format!("获取插件列表失败: {}", e)),
    }
}

pub fn show(bot: &RuntimeBot, event: &MsgEvent, parts: &[&str]) {
    let name = match parts.get(2) {
        Some(n) => n.to_string(),
        None => {
            event.reply("/acl show <插件名>");
            return;
        }
    };

    match bot.get_plugin_info() {
        Ok(plugins) => {
            let p = match plugins.iter().find(|p| p.name == name) {
                Some(p) => p,
                None => {
                    event.reply(format!("插件 '{}' 不存在。", name));
                    return;
                }
            };

            let mode_str = if is_whitelist(&p.list_mode) {
                "白名单"
            } else {
                "黑名单"
            };

            let mut lines = vec![format!(
                "{} v{}\n  启用: {}\n  访问控制: {}\n  模式: {}",
                p.name,
                p.version,
                if p.enabled { "是" } else { "否" },
                if p.access_control { "开启" } else { "关闭" },
                mode_str,
            )];

            if p.access_control {
                let groups: Vec<String> = p.access_list.groups.iter().map(|g| g.to_string()).collect();
                let friends: Vec<String> = p.access_list.friends.iter().map(|f| f.to_string()).collect();
                lines.push(format!("  群: {}", if groups.is_empty() { "无".to_string() } else { groups.join(", ") }));
                lines.push(format!("  好友: {}", if friends.is_empty() { "无".to_string() } else { friends.join(", ") }));
            }

            event.reply(lines.join("\n"));
        }
        Err(e) => event.reply(format!("获取插件信息失败: {}", e)),
    }
}

pub fn on(bot: &RuntimeBot, event: &MsgEvent, parts: &[&str]) {
    let name = match parts.get(2) {
        Some(n) => n.to_string(),
        None => {
            event.reply("/acl on <插件名>");
            return;
        }
    };

    if name == SELF_NAME {
        event.reply("不允许修改 ACL 插件自身的访问控制。");
        return;
    }

    match bot.set_plugin_access_control(&name, true) {
        Ok(()) => event.reply(format!("[OK] 已开启 {} 的访问控制。", name)),
        Err(e) => event.reply(format!("操作失败: {}", e)),
    }
}

pub fn off(bot: &RuntimeBot, event: &MsgEvent, parts: &[&str]) {
    let name = match parts.get(2) {
        Some(n) => n.to_string(),
        None => {
            event.reply("/acl off <插件名>");
            return;
        }
    };

    if name == SELF_NAME {
        event.reply("不允许修改 ACL 插件自身的访问控制。");
        return;
    }

    match bot.set_plugin_access_control(&name, false) {
        Ok(()) => event.reply(format!("[OK] 已关闭 {} 的访问控制。", name)),
        Err(e) => event.reply(format!("操作失败: {}", e)),
    }
}

pub fn mode(bot: &RuntimeBot, event: &MsgEvent, parts: &[&str], data_path: &Path) {
    let name = match parts.get(2) {
        Some(n) => n.to_string(),
        None => {
            event.reply("/acl mode <插件名> <whitelist|blacklist>");
            return;
        }
    };

    if name == SELF_NAME {
        event.reply("不允许修改 ACL 插件自身的访问控制。");
        return;
    }

    let acl_mode = match parts.get(3) {
        Some(&"whitelist" | &"白名单") => AccessControlMode::WhiteList,
        Some(&"blacklist" | &"黑名单") => AccessControlMode::BlackList,
        _ => {
            event.reply("模式必须是 whitelist(白名单) 或 blacklist(黑名单)。");
            return;
        }
    };

    let mode_str = if is_whitelist(&acl_mode) { "whitelist" } else { "blacklist" };
    let mode_cn = if is_whitelist(&acl_mode) { "白名单" } else { "黑名单" };

    // Save current list under current mode BEFORE switching
    crate::persist::save(bot, data_path);

    match bot.set_plugin_access_control_mode(&name, acl_mode) {
        Ok(()) => {
            crate::persist::apply_mode_list(bot, &name, mode_str, data_path);
            event.reply(format!("[OK] 已将 {} 设为{}模式。", name, mode_cn));
        }
        Err(e) => event.reply(format!("操作失败: {}", e)),
    }
}

pub fn add(bot: &RuntimeBot, event: &MsgEvent, parts: &[&str]) {
    let (name, is_group, id) = match parse_target(parts) {
        Some(v) => v,
        None => return,
    };

    if name == SELF_NAME {
        event.reply("不允许修改 ACL 插件自身的访问控制。");
        return;
    }

    match bot.set_plugin_access_control_list(&name, is_group, SetAccessControlList::Add(id)) {
        Ok(()) => {
            let target = if is_group { "群" } else { "好友" };
            event.reply(format!("[OK] 已将 {} {} 添加到 {} 的访问列表。", target, id, name));
        }
        Err(e) => event.reply(format!("操作失败: {}", e)),
    }
}

pub fn del(bot: &RuntimeBot, event: &MsgEvent, parts: &[&str]) {
    let (name, is_group, id) = match parse_target(parts) {
        Some(v) => v,
        None => return,
    };

    if name == SELF_NAME {
        event.reply("不允许修改 ACL 插件自身的访问控制。");
        return;
    }

    match bot.set_plugin_access_control_list(&name, is_group, SetAccessControlList::Remove(id)) {
        Ok(()) => {
            let target = if is_group { "群" } else { "好友" };
            event.reply(format!("[OK] 已将 {} {} 从 {} 的访问列表移除。", target, id, name));
        }
        Err(e) => event.reply(format!("操作失败: {}", e)),
    }
}

fn parse_target(parts: &[&str]) -> Option<(String, bool, i64)> {
    let name = parts.get(2)?;
    let kind = parts.get(3)?;
    let id_str = parts.get(4)?;
    let id: i64 = id_str.parse().ok()?;
    let is_group = match *kind {
        "group" | "群" => true,
        "friend" | "好友" => false,
        _ => return None,
    };
    Some((name.to_string(), is_group, id))
}

pub async fn reset(
    bot: &RuntimeBot,
    event: &MsgEvent,
    admin_id: i64,
    auth_state: &crate::auth::AuthState,
) {
    let code = crate::auth::generate_reset_code(auth_state, admin_id).await;

    bot.send_private_msg(admin_id, format!(
        "ACL WebUI 密码重置验证码: {}\n\n验证码 5 分钟内有效，请在 WebUI 登录页面点击「忘记密码」输入验证码和新密码。",
        code
    ));

    event.reply("验证码已通过私聊发送，请在 WebUI 登录页面点击「忘记密码」重置密码。");
}