import { useEffect, useState, useCallback } from "react";
import {
  fetchPlugins,
  setAcl,
  setMode,
  addGroup,
  removeGroup,
  addFriend,
  removeFriend,
  addGroups,
  addFriends,
  enablePlugin,
  disablePlugin,
  restartPlugin,
  fetchSystemInfo,
  login,
  changePassword,
  resetPassword,
  setToken,
  clearToken,
  isLoggedIn,
  type PluginInfo,
  type SystemInfo,
} from "./api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const SYSTEM_VIEW = "__system__";

// --- Change Password Dialog ---

function ChangePasswordDialog({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (next !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (next.length < 6) {
      setError("New password must be at least 6 characters");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await changePassword(current, next);
      setOk(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to change password");
    }
    setLoading(false);
  };

  if (ok) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
        <Card className="w-full max-w-sm" onClick={(e) => e.stopPropagation()}>
          <CardHeader>
            <CardTitle className="text-center text-lg">Password Changed</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <p className="text-sm text-muted-foreground text-center">
              All sessions have been invalidated. Please sign in again.
            </p>
            <Button className="w-full" onClick={() => { clearToken(); location.reload(); }}>
              Sign In Again
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <Card className="w-full max-w-sm" onClick={(e) => e.stopPropagation()}>
        <CardHeader>
          <CardTitle className="text-center text-lg">Change Password</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="flex flex-col gap-3">
            <Input
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              placeholder="Current password"
              autoFocus
            />
            <Input
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              placeholder="New password (min 6)"
            />
            <Input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Confirm new password"
            />
            {error && <p className="text-sm text-destructive">{error}</p>}
            <div className="flex gap-2">
              <Button type="button" variant="outline" className="flex-1" onClick={onClose}>Cancel</Button>
              <Button type="submit" className="flex-1" disabled={loading || !current || !next || !confirm}>
                {loading ? "Saving..." : "Save"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

// --- Login ---

function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showReset, setShowReset] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const token = await login(password);
      setToken(token);
      onLogin();
    } catch {
      setError("Invalid password");
    }
    setLoading(false);
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-muted">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-center text-lg">ACL</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="flex flex-col gap-4">
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              autoFocus
            />
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading || !password}>
              {loading ? "Signing in..." : "Sign in"}
            </Button>
          </form>
          <div className="mt-3 text-center">
            <button
              type="button"
              className="text-xs text-muted-foreground hover:text-foreground underline"
              onClick={() => setShowReset(true)}
            >
              Forgot password?
            </button>
          </div>
        </CardContent>
      </Card>
      {showReset && <ResetPasswordDialog onClose={() => setShowReset(false)} onReset={() => { setShowReset(false); }} />}
    </div>
  );
}

// --- Reset Password Dialog ---

function ResetPasswordDialog({ onClose, onReset }: { onClose: () => void; onReset: () => void }) {
  const [code, setCode] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (next !== confirm) {
      setError("Passwords do not match");
      return;
    }
    if (next.length < 6) {
      setError("New password must be at least 6 characters");
      return;
    }
    if (code.length === 0) {
      setError("Enter the reset code sent to your QQ");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await resetPassword(code, next);
      setOk(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reset failed");
    }
    setLoading(false);
  };

  if (ok) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
        <Card className="w-full max-w-sm" onClick={(e) => e.stopPropagation()}>
          <CardHeader>
            <CardTitle className="text-center text-lg">Password Reset</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <p className="text-sm text-muted-foreground text-center">
              Password has been reset. Please sign in with your new password.
            </p>
            <Button className="w-full" onClick={onReset}>Sign In</Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <Card className="w-full max-w-sm" onClick={(e) => e.stopPropagation()}>
        <CardHeader>
          <CardTitle className="text-center text-lg">Reset Password</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-xs text-muted-foreground">
            Send <span className="font-mono">/acl reset</span> to the bot on QQ to receive a reset code, then enter it below.
          </p>
          <form onSubmit={submit} className="flex flex-col gap-3">
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Reset code"
              autoFocus
              className="font-mono"
            />
            <Input
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              placeholder="New password (min 6)"
            />
            <Input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Confirm new password"
            />
            {error && <p className="text-sm text-destructive">{error}</p>}
            <div className="flex gap-2">
              <Button type="button" variant="outline" className="flex-1" onClick={onClose}>Cancel</Button>
              <Button type="submit" className="flex-1" disabled={loading || !code || !next || !confirm}>
                {loading ? "Resetting..." : "Reset"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

// --- Sidebar ---

function Sidebar({
  plugins,
  selected,
  onSelect,
}: {
  plugins: PluginInfo[];
  selected: string | null;
  onSelect: (name: string) => void;
}) {
  const [search, setSearch] = useState("");
  const q = search.toLowerCase();
  const filtered = q
    ? plugins.filter((p) => {
        const n = p.name.toLowerCase();
        let i = 0;
        for (const c of q) {
          i = n.indexOf(c, i) + 1;
          if (!i) return false;
        }
        return true;
      })
    : plugins;

  return (
    <div className="flex w-72 shrink-0 flex-col border-r bg-background">
      <div className="flex items-center justify-between border-b px-4 py-3">
        <span className="text-sm font-semibold">ACL</span>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs text-muted-foreground"
            onClick={() => { clearToken(); location.reload(); }}
          >
            Logout
          </Button>
        </div>
      </div>
      <div className="border-b px-3 py-2">
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search plugins..."
          className="h-8 text-sm"
        />
      </div>
      <div className="flex-1 overflow-auto py-1">
        {filtered.map((p) => (
          <button
            key={p.name}
            onClick={() => onSelect(p.name)}
            className={`w-full px-4 py-2.5 text-left transition-colors ${
              p.name === selected
                ? "bg-accent text-accent-foreground"
                : "text-foreground hover:bg-muted/50"
            } ${!p.enabled ? "opacity-50" : ""}`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-sm font-medium">{p.name}</span>
              <span className="shrink-0 text-xs text-muted-foreground tabular-nums">
                v{p.version}
              </span>
            </div>
            <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
              {p.enabled ? (
                <>
                  <span
                    className={`inline-block size-1.5 rounded-full ${
                      p.access_control
                        ? p.list_mode === "whitelist"
                          ? "bg-primary"
                          : "bg-destructive"
                        : "bg-muted-foreground/40"
                    }`}
                  />
                  {p.access_control
                    ? `${p.list_mode === "whitelist" ? "Whitelist" : "Blacklist"} · ${p.groups.length}g ${p.friends.length}f`
                    : "ACL off"}
                </>
              ) : (
                "Disabled"
              )}
            </div>
          </button>
        ))}
        {filtered.length === 0 && (
          <p className="px-4 py-6 text-center text-xs text-muted-foreground">
            {plugins.length === 0 ? "No plugins loaded." : "No match."}
          </p>
        )}
      </div>
      <div className="border-t">
        <button
          onClick={() => onSelect(SYSTEM_VIEW)}
          className={`w-full px-4 py-3 text-left text-sm transition-colors ${
            selected === SYSTEM_VIEW
              ? "bg-accent text-accent-foreground"
              : "text-foreground hover:bg-muted/50"
          }`}
        >
          System
        </button>
      </div>
    </div>
  );
}

// --- System Panel ---

function SystemPanel({ sysInfo, onChangePassword }: { sysInfo: SystemInfo | null; onChangePassword: () => void }) {
  if (!sysInfo) {
    return (
      <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
        Loading system info...
      </div>
    );
  }

  const uptime =
    sysInfo.uptime_secs < 3600
      ? `${Math.floor(sysInfo.uptime_secs / 60)}m`
      : sysInfo.uptime_secs < 86400
        ? `${Math.floor(sysInfo.uptime_secs / 3600)}h ${Math.floor((sysInfo.uptime_secs % 3600) / 60)}m`
        : `${Math.floor(sysInfo.uptime_secs / 86400)}d ${Math.floor((sysInfo.uptime_secs % 86400) / 3600)}h`;

  const ob = sysInfo.onebot_version as Record<string, unknown> | null | undefined;
  const obName = ob?.app_name as string | undefined;
  const obVer = ob?.app_version as string | undefined;

  return (
    <div className="flex flex-1 flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b px-6 py-4">
        <h1 className="text-lg font-semibold">System</h1>
        <Button variant="outline" size="sm" className="h-7 text-xs" onClick={onChangePassword}>
          Change Password
        </Button>
      </div>
      <div className="flex-1 overflow-y-auto p-6">
        <div className="grid grid-cols-2 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Runtime</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Uptime</span>
                <span className="tabular-nums font-medium">{uptime}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Started</span>
                <span className="tabular-nums">
                  {new Date(sysInfo.start_time).toLocaleDateString()}{" "}
                  {new Date(sysInfo.start_time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Plugins</span>
                <span className="tabular-nums font-medium">{sysInfo.plugin_count}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Memory</span>
                <span className="tabular-nums">
                  {sysInfo.memory_used_mb} / {sysInfo.memory_total_mb} MB
                </span>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">OneBot</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {obName ? (
                <>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Implementation</span>
                    <span className="truncate ml-4 text-right font-medium">{obName}</span>
                  </div>
                  {obVer && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Version</span>
                      <span className="tabular-nums font-medium">{obVer}</span>
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-muted-foreground italic">Not available</p>
              )}
            </CardContent>
          </Card>
          <Card className="col-span-2">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Administrators</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="flex items-center justify-between rounded-md border px-3 py-2">
                  <span className="text-sm text-muted-foreground">Main Admin</span>
                  <span className="font-mono text-sm tabular-nums font-medium">{sysInfo.main_admin}</span>
                </div>
                {sysInfo.admins.length > 0 && (
                  <div className="rounded-md border px-3 py-2">
                    <span className="text-sm text-muted-foreground">Deputy Admins</span>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {sysInfo.admins.map((id) => (
                        <span
                          key={id}
                          className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 font-mono text-xs tabular-nums"
                        >
                          {id}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {sysInfo.admins.length === 0 && (
                  <p className="text-sm text-muted-foreground italic">No deputy admins configured</p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

// --- ID List ---

function IdList({
  label,
  ids,
  onAdd,
  onAddBatch,
  onRemove,
  loading,
  placeholder,
}: {
  label: string;
  ids: number[];
  onAdd: (id: number) => void;
  onAddBatch: (ids: number[]) => void;
  onRemove: (id: number) => void;
  loading: boolean;
  placeholder: string;
}) {
  const [value, setValue] = useState("");

  const parseIds = (v: string): number[] =>
    v.trim().split(/\s+/).map(Number).filter((n) => !isNaN(n));

  const handleAdd = () => {
    const parsed = parseIds(value);
    if (parsed.length === 0) return;
    if (parsed.length === 1) {
      onAdd(parsed[0]);
    } else {
      onAddBatch(parsed);
    }
    setValue("");
  };

  return (
    <div className="flex flex-col gap-2">
      <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {label}{" "}
        <span className="tabular-nums">{ids.length}</span>
      </span>
      <div className="flex gap-1.5">
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={`${placeholder} (space-separated)`}
          className="h-8 flex-1 font-mono text-sm tabular-nums"
          onKeyDown={(e) => e.key === "Enter" && handleAdd()}
        />
        <Button
          variant="outline"
          size="sm"
          className="h-8"
          disabled={loading || parseIds(value).length === 0}
          onClick={handleAdd}
        >
          Add
        </Button>
      </div>
      <div className="flex flex-col gap-1">
        {ids.map((id) => (
          <div
            key={id}
            className="group flex items-center justify-between rounded-md border px-2.5 py-1.5 hover:bg-muted/50"
          >
            <span className="font-mono text-sm tabular-nums">{id}</span>
            <button
              className="text-muted-foreground opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100"
              disabled={loading}
              onClick={() => onRemove(id)}
            >
              &times;
            </button>
          </div>
        ))}
        {ids.length === 0 && (
          <p className="py-3 text-xs text-muted-foreground italic">
            No {label.toLowerCase()} added
          </p>
        )}
      </div>
    </div>
  );
}

// --- Detail Panel ---

function DetailPanel({
  plugin,
  onRefresh,
}: {
  plugin: PluginInfo;
  onRefresh: () => void;
}) {
  const [loading, setLoading] = useState(false);

  const act = async (fn: () => Promise<void>) => {
    setLoading(true);
    try {
      await fn();
      onRefresh();
    } catch (e) {
      alert(e instanceof Error ? e.message : "Request failed");
    }
    setLoading(false);
  };

  return (
    <div className="flex flex-1 flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b px-6 py-4">
        <div className="flex items-baseline gap-2">
          <h1 className="text-lg font-semibold">{plugin.name}</h1>
          <span className="text-sm text-muted-foreground tabular-nums">
            v{plugin.version}
          </span>
          {!plugin.enabled && (
            <span className="text-sm text-destructive">Disabled</span>
          )}
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              disabled={loading}
              onClick={() => act(() => restartPlugin(plugin.name))}
            >
              Restart
            </Button>
            {plugin.enabled ? (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                disabled={loading}
                onClick={() => act(() => disablePlugin(plugin.name))}
              >
                Disable
              </Button>
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                disabled={loading}
                onClick={() => act(() => enablePlugin(plugin.name))}
              >
                Enable
              </Button>
            )}
          </div>
          <div className="h-4 w-px bg-border" />
          <div className="flex items-center gap-3">
            <span className="text-sm text-muted-foreground">Access Control</span>
            <div className="flex items-center gap-2">
              <Switch
                checked={plugin.access_control}
                disabled={loading || !plugin.enabled}
                onCheckedChange={(checked: boolean) =>
                  act(() => setAcl(plugin.name, checked))
                }
              />
              <span className="text-sm tabular-nums text-muted-foreground">
                {plugin.access_control ? "On" : "Off"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Mode toggle */}
      <div
        className={`flex items-center gap-2 border-b px-6 py-3 ${
          !plugin.access_control ? "pointer-events-none opacity-40" : ""
        }`}
      >
        <div className="flex rounded-md border">
          <button
            className={`px-3 py-1.5 text-sm transition-colors ${
              plugin.list_mode === "whitelist"
                ? "bg-primary text-primary-foreground"
                : "bg-background text-foreground hover:bg-muted"
            }`}
            disabled={loading || !plugin.access_control}
            onClick={() =>
              plugin.list_mode !== "whitelist" &&
              act(() => setMode(plugin.name, "whitelist"))
            }
          >
            Whitelist
          </button>
          <button
            className={`px-3 py-1.5 text-sm transition-colors ${
              plugin.list_mode === "blacklist"
                ? "bg-primary text-primary-foreground"
                : "bg-background text-foreground hover:bg-muted"
            }`}
            disabled={loading || !plugin.access_control}
            onClick={() =>
              plugin.list_mode !== "blacklist" &&
              act(() => setMode(plugin.name, "blacklist"))
            }
          >
            Blacklist
          </button>
        </div>
        <span className="text-xs text-muted-foreground">
          {plugin.list_mode === "whitelist"
            ? "Only listed groups and friends can use this plugin"
            : "Listed groups and friends are blocked from this plugin"}
        </span>
      </div>

      {/* Body */}
      <div
        className={`flex-1 overflow-y-auto p-6 ${
          !plugin.access_control || !plugin.enabled
            ? "pointer-events-none opacity-40"
            : ""
        }`}
      >
        <div className="grid grid-cols-2 gap-4">
          <Card>
            <CardContent className="p-4">
              <IdList
                label="Groups"
                ids={plugin.groups}
                onAdd={(id) => act(() => addGroup(plugin.name, id))}
                onAddBatch={(ids) => act(() => addGroups(plugin.name, ids))}
                onRemove={(id) => act(() => removeGroup(plugin.name, id))}
                loading={loading}
                placeholder="Group ID"
              />
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <IdList
                label="Friends"
                ids={plugin.friends}
                onAdd={(id) => act(() => addFriend(plugin.name, id))}
                onAddBatch={(ids) => act(() => addFriends(plugin.name, ids))}
                onRemove={(id) => act(() => removeFriend(plugin.name, id))}
                loading={loading}
                placeholder="Friend ID"
              />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

// --- App ---

export default function App() {
  const [authed, setAuthed] = useState(isLoggedIn());
  const [plugins, setPlugins] = useState<PluginInfo[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [sysInfo, setSysInfo] = useState<SystemInfo | null>(null);
  const [showPwDialog, setShowPwDialog] = useState(false);

  const load = useCallback(() => {
    fetchPlugins()
      .then((list) => {
        setPlugins(list);
        if (selected !== SYSTEM_VIEW && !list.find((p) => p.name === selected)) {
          setSelected(list[0]?.name ?? null);
        }
      })
      .catch((e) => {
        if (e.status === 401) setAuthed(false);
      });
    fetchSystemInfo().then(setSysInfo).catch(() => {});
  }, [selected]);

  useEffect(() => {
    if (!authed) return;
    load();
    const iv = setInterval(load, 10000);
    return () => clearInterval(iv);
  }, [authed, load]);

  if (!authed) {
    return <LoginPage onLogin={() => { setAuthed(true); }} />;
  }

  const current = selected === SYSTEM_VIEW ? null : plugins.find((p) => p.name === selected) ?? null;

  return (
    <div className="flex h-screen">
      <Sidebar plugins={plugins} selected={selected} onSelect={setSelected} />
      {showPwDialog && <ChangePasswordDialog onClose={() => setShowPwDialog(false)} />}
      {selected === SYSTEM_VIEW ? (
        <SystemPanel sysInfo={sysInfo} onChangePassword={() => setShowPwDialog(true)} />
      ) : current ? (
        <DetailPanel plugin={current} onRefresh={load} />
      ) : (
        <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
          Select a plugin
        </div>
      )}
    </div>
  );
}