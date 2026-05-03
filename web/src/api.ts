export interface PluginInfo {
  name: string;
  version: string;
  enabled: boolean;
  access_control: boolean;
  list_mode: "whitelist" | "blacklist";
  groups: number[];
  friends: number[];
}

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

class AuthError extends ApiError {
  constructor() {
    super(401, "unauthorized");
  }
}

function getToken(): string | null {
  return localStorage.getItem("acl_token");
}

export function setToken(token: string) {
  localStorage.setItem("acl_token", token);
}

export function clearToken() {
  localStorage.removeItem("acl_token");
}

export function isLoggedIn(): boolean {
  return !!getToken();
}

async function request<T>(
  path: string,
  opts?: RequestInit,
): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) throw new AuthError();
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, body);
  }
  return res.json();
}

export async function login(password: string): Promise<string> {
  const data = await request<{ token: string }>("/api/login", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
  return data.token;
}

export async function fetchPlugins(): Promise<PluginInfo[]> {
  return request<PluginInfo[]>("/api/plugins");
}

export async function setAcl(name: string, enabled: boolean) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/acl", {
    method: "POST",
    body: JSON.stringify({ enabled }),
  });
}

export async function setMode(name: string, mode: "whitelist" | "blacklist") {
  await request("/api/plugins/" + encodeURIComponent(name) + "/mode", {
    method: "POST",
    body: JSON.stringify({ mode }),
  });
}

export async function addGroup(name: string, id: number) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/groups", {
    method: "POST",
    body: JSON.stringify({ id }),
  });
}

export async function removeGroup(name: string, id: number) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/groups", {
    method: "DELETE",
    body: JSON.stringify({ id }),
  });
}

export async function addFriend(name: string, id: number) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/friends", {
    method: "POST",
    body: JSON.stringify({ id }),
  });
}

export async function removeFriend(name: string, id: number) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/friends", {
    method: "DELETE",
    body: JSON.stringify({ id }),
  });
}

// Batch ACL
export async function addGroups(name: string, ids: number[]) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/groups/batch", {
    method: "POST",
    body: JSON.stringify({ ids }),
  });
}

export async function removeGroups(name: string, ids: number[]) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/groups/batch", {
    method: "DELETE",
    body: JSON.stringify({ ids }),
  });
}

export async function addFriends(name: string, ids: number[]) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/friends/batch", {
    method: "POST",
    body: JSON.stringify({ ids }),
  });
}

export async function removeFriends(name: string, ids: number[]) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/friends/batch", {
    method: "DELETE",
    body: JSON.stringify({ ids }),
  });
}

// Plugin management
export async function enablePlugin(name: string) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/enable", {
    method: "POST",
  });
}

export async function disablePlugin(name: string) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/disable", {
    method: "POST",
  });
}

export async function restartPlugin(name: string) {
  await request("/api/plugins/" + encodeURIComponent(name) + "/restart", {
    method: "POST",
  });
}

// Auth
export async function changePassword(current: string, next: string) {
  await request("/api/password", {
    method: "POST",
    body: JSON.stringify({ current, new: next }),
  });
}

export async function resetPassword(code: string, next: string) {
  await request("/api/reset-password", {
    method: "POST",
    body: JSON.stringify({ code, new: next }),
  });
}

// System
export interface SystemInfo {
  start_time: string;
  uptime_secs: number;
  plugin_count: number;
  memory_used_mb: number;
  memory_total_mb: number;
  onebot_version: unknown;
  main_admin: number;
  admins: number[];
}

export async function fetchSystemInfo(): Promise<SystemInfo> {
  return request<SystemInfo>("/api/system");
}