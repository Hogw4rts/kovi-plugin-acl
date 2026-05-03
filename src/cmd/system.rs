use kovi::MsgEvent;
use sysinfo::System;

pub fn status(start_time: chrono::DateTime<chrono::Utc>, event: &MsgEvent) {
    let mut sys = System::new_all();
    sys.refresh_memory();

    let uptime = (chrono::Utc::now() - start_time).num_seconds();
    let uptime_str = if uptime < 3600 {
        format!("{}分", uptime / 60)
    } else if uptime < 86400 {
        format!("{}小时{}分", uptime / 3600, (uptime % 3600) / 60)
    } else {
        format!("{}天{}小时", uptime / 86400, (uptime % 86400) / 3600)
    };

    let used_mb = sys.used_memory() / 1024 / 1024;
    let total_mb = sys.total_memory() / 1024 / 1024;

    event.reply(format!(
        "运行时间: {}\n内存: {}MB / {}MB",
        uptime_str, used_mb, total_mb
    ));
}