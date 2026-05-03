use chrono::{DateTime, Utc};
use kovi::log::info;
use kovi::PluginBuilder as plugin;
use std::path::PathBuf;
use std::sync::Arc;

mod api;
mod auth;
mod cmd;
mod persist;
mod web;

static START_TIME: std::sync::OnceLock<DateTime<Utc>> = std::sync::OnceLock::new();
pub(crate) static DATA_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

#[kovi::plugin]
async fn main() {
    let start_time = *START_TIME.get_or_init(Utc::now);
    let bot = plugin::get_runtime_bot();
    let data_path = DATA_PATH.get_or_init(|| bot.get_data_path()).clone();
    let web_data_path = data_path.clone();
    let data_path = Arc::new(data_path);

    let auth_state = auth::init_auth(&data_path);

    persist::load_and_apply(&bot, &data_path);
    info!("ACL plugin loaded. Commands: /acl, /plugin, /sys");

    let cmd_auth = auth_state.clone();
    plugin::on_msg(move |event| {
        let start_time = start_time;
        let data_path = data_path.clone();
        let bot = bot.clone();
        let auth_state = cmd_auth.clone();
        async move {
            let text = match event.borrow_text() {
                Some(t) => t.trim().to_string(),
                None => return,
            };

            let user_id = event.sender.user_id;
            match bot.get_all_admin() {
                Ok(admins) => {
                    if !admins.contains(&user_id) {
                        return;
                    }
                }
                Err(_) => return,
            }

            let parts: Vec<&str> = text.split_whitespace().collect();
            if parts.is_empty() {
                return;
            }

            match parts[0] {
                "/acl" => {
                    if parts.len() < 2 {
                        event.reply("/acl list | show <name> | on <name> | off <name> | mode <name> <whitelist|blacklist> | add <name> group|friend <id> | del <name> group|friend <id> | reset");
                        return;
                    }
                    match parts[1] {
                        "list" => cmd::acl::list(&bot, &event),
                        "show" => cmd::acl::show(&bot, &event, &parts),
                        "on" => { cmd::acl::on(&bot, &event, &parts); persist::save(&bot, &*data_path); }
                        "off" => { cmd::acl::off(&bot, &event, &parts); persist::save(&bot, &*data_path); }
                        "mode" => cmd::acl::mode(&bot, &event, &parts, &data_path),
                        "add" => { cmd::acl::add(&bot, &event, &parts); persist::save(&bot, &*data_path); }
                        "del" => { cmd::acl::del(&bot, &event, &parts); persist::save(&bot, &*data_path); }
                        "reset" => cmd::acl::reset(&bot, &event, user_id, &auth_state).await,
                        _ => event.reply("未知子命令。可用: list, show, on, off, mode, add, del, reset"),
                    }
                }
                "/plugin" => {
                    if parts.len() < 3 {
                        event.reply("/plugin start|stop|restart <name>");
                        return;
                    }
                    let name = parts[2];
                    match parts[1] {
                        "start" | "enable" => cmd::plugin::enable(&bot, &event, name).await,
                        "stop" | "disable" => cmd::plugin::disable(&bot, &event, name).await,
                        "restart" => cmd::plugin::restart(&bot, &event, name).await,
                        _ => event.reply("未知子命令。可用: start, stop, restart"),
                    }
                }
                "/sys" => {
                    cmd::system::status(start_time, &event);
                }
                _ => {}
            }
        }
    });

    let bot = plugin::get_runtime_bot();
    let web_start_time = start_time;
    tokio::spawn(async move {
        if let Err(e) = web::start_with_start_time(bot, web_start_time, web_data_path, auth_state).await {
            info!("ACL WebUI error: {}", e);
        }
    });
}