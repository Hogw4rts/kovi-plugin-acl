use kovi::MsgEvent;
use kovi::RuntimeBot;

const SELF_NAME: &str = env!("CARGO_PKG_NAME");

pub async fn enable(bot: &RuntimeBot, event: &MsgEvent, name: &str) {
    if name.is_empty() {
        event.reply("/plugin start <插件名>");
        return;
    }

    if name == SELF_NAME {
        event.reply("ACL 插件始终处于启用状态。");
        return;
    }

    match bot.enable_plugin(name) {
        Ok(()) => event.reply(format!("[OK] 已启用插件 {}。", name)),
        Err(e) => event.reply(format!("操作失败: {}", e)),
    }
}

pub async fn disable(bot: &RuntimeBot, event: &MsgEvent, name: &str) {
    if name.is_empty() {
        event.reply("/plugin stop <插件名>");
        return;
    }

    if name == SELF_NAME {
        event.reply("不允许禁用 ACL 插件自身。");
        return;
    }

    match bot.disable_plugin(name) {
        Ok(_) => event.reply(format!("[OK] 已禁用插件 {}。", name)),
        Err(e) => event.reply(format!("操作失败: {}", e)),
    }
}

pub async fn restart(bot: &RuntimeBot, event: &MsgEvent, name: &str) {
    if name.is_empty() {
        event.reply("/plugin restart <插件名>");
        return;
    }

    if name == SELF_NAME {
        event.reply("不允许重启 ACL 插件自身。");
        return;
    }

    match bot.restart_plugin(name).await {
        Ok(()) => event.reply(format!("[OK] 已重启插件 {}。", name)),
        Err(e) => event.reply(format!("操作失败: {}", e)),
    }
}