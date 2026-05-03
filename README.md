# kovi-plugin-acl

Kovi 框架的动态访问控制列表（ACL）管理插件，支持 QQ 指令和 WebUI。

## 功能

- **QQ 指令** — `/acl list`、`/acl show <插件名>`、`/acl on|off <插件名>`、`/acl mode <插件名> <whitelist|blacklist>`、`/acl add|del <插件名> group|friend <ID>`、`/acl reset`
- **WebUI** — 浏览器管理面板，地址 `http://0.0.0.0:5800`，支持插件管理、ACL 编辑、批量操作、模糊搜索
- **JWT 认证** — 密码登录，JWT 令牌（24 小时有效期），按 IP 限流
- **密码重置** — 管理员发送 `/acl reset`，通过 QQ 私聊接收验证码，在 WebUI 登录页输入验证码和新密码完成重置
- **持久化存储** — 密码和 JWT 密钥存储在 `auth.json`；每个插件的白名单/黑名单独立存储
- **模式切换** — 白名单/黑名单之间切换时，各自的列表独立保存，切换回来可恢复
- **前端内嵌** — WebUI 编译进二进制，`cargo add` 后无需额外配置即可使用
- **System 页面** — 运行时信息（uptime、启动时间、插件数、内存）、OneBot 实现/版本、管理员列表（主管理员 + 副管理员）

## 安装

```bash
cargo add kovi-plugin-acl --git https://github.com/Hogw4rts/kovi-plugin-acl.git
```

或在 `Cargo.toml` 中添加：

```toml
[dependencies]
kovi-plugin-acl = { git = "https://github.com/Hogw4rts/kovi-plugin-acl.git" }
```

然后在 `main.rs` 中引入：

```rust
use kovi::build_bot;
use kovi_plugin_acl;

fn main() {
    let bot = build_bot!(kovi_plugin_acl);
    bot.run();
}
```

`cargo add` 后直接可用，WebUI 已内嵌在二进制中，无需额外配置或构建前端。

## 管理员配置

QQ 指令和 WebUI 均需要管理员权限。管理员在 Kovi 的配置文件 `kovi.conf.toml` 中设置：

```toml
[config]
main_admin = 123456789       # 主管理员
admins = [987654321, 111222] # 副管理员列表
```

**注意**：修改管理员配置后需要重启 Kovi 才能生效。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `ACL_PORT` | `5800` | WebUI 监听端口 |
| `ACL_PASSWORD` | *自动生成* | 初始密码（启动时打印一次） |

## 设计

### 架构

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  QQ 客户端   │────▶│  on_msg cmd  │     │   浏览器     │
└─────────────┘     │  (acl.rs)    │     └──────┬──────┘
                    └──────┬───────┘              │
                           │              ┌──────▼──────┐
                      ┌────▼────┐         │  axum Router │
                      │RuntimeBot│        │  (api.rs)    │
                      │  (Kovi)  │        └──────┬──────┘
                      └────┬────┘               │
                           │              ┌──────▼──────┐
                    ┌──────▼───────┐      │ auth.rs     │
                    │  persist.rs  │      │ (JWT+登录)  │
                    │ (ACL 列表)   │      └─────────────┘
                    └──────────────┘
```

两个入口共享同一个 `RuntimeBot` 实例：

1. **QQ 指令**（`src/cmd/acl.rs`）— 处理 `/acl` 群聊/私聊消息
2. **HTTP API**（`src/api.rs`）— RESTful 接口，供 React 前端调用

两条路径都调用 `RuntimeBot` 方法（`set_plugin_access_control`、`set_plugin_access_control_list`、`set_plugin_access_control_mode`），并通过 `persist.rs` 持久化。

### ACL 持久化（persist.rs）

每个插件的白名单和黑名单**独立存储**在 `./data/kovi-plugin-acl/<插件名>.json`：

```json
{
  "whitelist": { "groups": [123, 456], "friends": [789] },
  "blacklist": { "groups": [], "friends": [] }
}
```

**模式切换流程**（关键路径）：

1. `save()` — 将当前列表保存到当前模式对应的字段（如当前是白名单模式，写入 `whitelist` 字段）
2. `set_plugin_access_control_mode()` — 通知 Kovi 切换模式（此操作会清空内存中的列表）
3. `apply_mode_list()` — 从磁盘加载目标模式的列表，通过 `SetAccessControlList::Changes` 写入 Kovi

这样两个列表在模式切换时互不覆盖。白名单→黑名单→白名单可以恢复原始白名单。

### 认证（auth.rs）

- **密码**：SHA-256 哈希，存储在 `auth.json`，同时存储一个随机 32 字节 JWT 签名密钥
- **首次启动**：密码自动生成（或通过 `ACL_PASSWORD` 环境变量设置），打印一次到日志
- **JWT**：HS256 签名，24 小时有效期；修改密码时密钥轮换，所有会话失效
- **限流**：按 IP 滑动窗口 — 登录 10 次/分钟，认证失败 30 次/分钟，密码重置 5 次/5 分钟
- **密码重置**：管理员在 QQ 发送 `/acl reset`，bot 私聊发送 6 位验证码（5 分钟有效），在 WebUI 登录页输入验证码和新密码完成重置。重置后 JWT 密钥轮换，所有旧会话失效
- **损坏恢复**：如果 `auth.json` 被截断或包含无效 hex，`init_auth` 会重新生成凭据而非 panic

### 前端内嵌

WebUI 的构建产物（`web/dist`）通过 `include_dir!` 在编译时嵌入二进制，运行时无需外部文件。`cargo add` 后直接可用，无需额外配置。

### HTTP 层（api.rs + web.rs）

- axum 路由，使用 `ConnectInfo<SocketAddr>` 实现按 IP 限流
- 认证中间件在所有 `/api/*` 路由（除 `/api/login` 和 `/api/reset-password`）上验证 JWT
- CORS 配置支持跨域开发
- `tower-http` 提供 30 秒请求超时
- 静态文件从嵌入式资源提供，`index.html` 作为 SPA 回退

### 前端（web）

- React + TypeScript + Vite
- shadcn/ui 组件 + Tailwind v4
- 模糊搜索（子序列匹配）过滤插件
- 批量 ID 输入（空格分隔）批量添加群/好友
- 修改密码对话框（修改后需重新登录）
- 忘记密码对话框 — 输入验证码和新密码重置
- 独立 System 页面 — 运行时信息、OneBot 版本、管理员列表

## 开发

修改前端后需要重新构建：

```bash
cd web && npm install && npm run build
```

后端编译时会自动嵌入最新的 `web/dist`。

## 许可证

GPL-3.0