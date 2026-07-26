import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Boxes,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  CircleDot,
  Code2,
  Database,
  Download,
  FileJson,
  FileSearch,
  Gauge,
  Hammer,
  HardDriveUpload,
  LayoutDashboard,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  ShieldCheck,
  Square,
  Terminal,
  Trash2,
  Wrench,
  X,
  Zap,
} from "lucide-react";
import {
  fetchCatalog,
  type CatalogItem,
  type CatalogKind,
} from "./api/catalog";

type View =
  | "overview"
  | "experiments"
  | "catalog"
  | "providers"
  | "environment"
  | "knowledge"
  | "access";
type ReconstructionState = {
  stage: string;
  analysis_complete: boolean;
  source_generated: boolean;
  structure_complete: boolean;
  dependencies_locked: boolean;
  build_passed: boolean;
  behavior_passed: boolean;
  complete_buildable: boolean;
  iteration: number;
  blocking_reasons: string[];
  updated_at?: string;
};
type Experiment = {
  id: string;
  sample: string;
  name: string;
  status: string;
  created_at?: string;
  updated_at?: string;
  options: Record<string, unknown>;
  artifacts: Array<Record<string, unknown>>;
  summary?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  reconstruction?: ReconstructionState;
  error?: string;
};
type EventRecord = {
  sequence: number;
  timestamp: string;
  type: string;
  status?: string;
  message: string;
  data?: Record<string, unknown>;
};
type EnvironmentPayload = {
  summary: Record<string, number>;
  workflows: Array<{
    id: string;
    status: string;
    verified?: boolean;
    missing?: string[];
    note?: string;
  }>;
  acceptance_fixtures: Array<{
    id: string;
    phase?: string;
    capability?: string;
    status: string;
    live_verified?: boolean;
    missing_gates?: string[];
    command?: string;
  }>;
  sandbox?: Record<string, unknown>;
  storage?: Record<string, unknown>;
  providers?: Array<Record<string, unknown>>;
};
type Knowledge = {
  id: string;
  title?: string;
  content?: string;
  type?: string;
  tags?: string[];
  updated_at?: string;
};
type Provider = {
  name: string;
  kind: string;
  protocol?: "responses" | "chat_completions";
  model?: string;
  base_url?: string;
  api_keys?: string[];
  key_count?: number;
  enabled: boolean;
  priority: number;
  models?: Array<{
    id: string;
    display_name?: string;
    priority: number;
    enabled: boolean;
  }>;
  usage?: {
    Requests?: number;
    Failures?: number;
    InputTokens?: number;
    OutputTokens?: number;
    requests?: number;
    failures?: number;
    input_tokens?: number;
    output_tokens?: number;
  };
};
type Identity = { subject: string; role: string } | null;
type Workspace = {
  mode: string;
  workspace: string;
  summary: Record<string, number | Record<string, number> | null>;
  experiments: Experiment[];
  knowledge: Knowledge[];
  environment?: EnvironmentPayload;
};

const EMPTY: Workspace = {
  mode: "offline",
  workspace: "",
  summary: {},
  experiments: [],
  knowledge: [],
};
const CONFIRMATION = "EXECUTE_LOCAL_ANALYSIS";
const NAV = [
  {
    id: "overview" as View,
    label: "态势总览",
    hint: "运行状态与风险",
    icon: LayoutDashboard,
  },
  {
    id: "experiments" as View,
    label: "流程工作台",
    hint: "计划、执行与复核",
    icon: FileSearch,
  },
  {
    id: "catalog" as View,
    label: "平台目录",
    hint: "技能、工具与依赖",
    icon: Boxes,
  },
  {
    id: "providers" as View,
    label: "模型服务管理",
    hint: "模型、连接与用量",
    icon: Zap,
  },
  {
    id: "environment" as View,
    label: "环境验收",
    hint: "沙箱、存储与真实门禁",
    icon: Terminal,
  },
  {
    id: "knowledge" as View,
    label: "知识库",
    hint: "经验沉淀与召回",
    icon: BookOpen,
  },
  {
    id: "access" as View,
    label: "访问控制",
    hint: "角色、令牌与撤销",
    icon: ShieldCheck,
  },
];

function headers(extra: Record<string, string> = {}) {
  const token = localStorage.getItem("reverseAnalyzerWebToken") || "";
  return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
}
function initialAccessToken() {
  return localStorage.getItem("reverseAnalyzerWebToken") || "";
}

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [data, setData] = useState<Workspace>(EMPTY);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [drawer, setDrawer] = useState<Experiment | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [token, setToken] = useState(initialAccessToken);
  const [identity, setIdentity] = useState<Identity>(null);
  const [catalog, setCatalog] = useState<CatalogItem[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [catalogAsset, setCatalogAsset] = useState<CatalogItem | null>(null);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [providersLoading, setProvidersLoading] = useState(false);
  const refresh = async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/workspace", {
        cache: "no-store",
        headers: headers(),
      });
      const p = await r.json();
      if (!r.ok)
        throw new Error(
          r.status === 401
            ? "需要访问令牌，请在右上角输入管理员令牌并按回车键"
            : p.error || `接口返回 ${r.status}`,
        );
      setData(p);
      const me = await fetch("/api/auth/me", { headers: headers(), cache: "no-store" });
      if (me.ok) setIdentity(await me.json());
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "无法连接服务");
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    const code = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("oauth_code");
    if (!code) return;
    history.replaceState(null, "", window.location.pathname + window.location.search);
    void fetch("/api/auth/oauth/exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    }).then(async (response) => {
      const payload = await response.json();
      if (!response.ok || !payload.token) throw new Error("OAuth 登录凭据已失效，请重新登录");
      localStorage.setItem("reverseAnalyzerWebToken", payload.token);
      setToken(payload.token);
      await refresh();
    }).catch((reason) => setError(reason instanceof Error ? reason.message : "OAuth 登录失败"));
  }, []);
  useEffect(() => {
    void refresh();
  }, []);
  useEffect(() => {
    if (view !== "catalog") return;
    setCatalogLoading(true);
    fetchCatalog()
      .then((p) => setCatalog(p.items))
      .catch((e) => setError(String(e)))
      .finally(() => setCatalogLoading(false));
  }, [view]);
  const refreshProviders = async () => {
    setProvidersLoading(true);
    try {
      const r = await fetch("/api/providers", {
        headers: headers(),
        cache: "no-store",
      });
      const p = await r.json();
      if (!r.ok) throw new Error(p.error || `模型服务接口返回 ${r.status}`);
      setProviders(p.providers || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setProvidersLoading(false);
    }
  };
  useEffect(() => {
    if (view === "providers" && identity?.role === "admin")
      void refreshProviders();
  }, [view, identity?.role]);
  useEffect(() => {
    if (!drawer) return;
    const controller = new AbortController();
    const id = drawer.id;
    const syncExperiment = async () => {
      const r = await fetch(`/api/experiments/${id}`, {
        headers: headers(),
        cache: "no-store",
        signal: controller.signal,
      });
      if (r.ok) setDrawer(await r.json());
    };
    const stream = async () => {
      setEvents([]);
      const r = await fetch(`/api/experiments/${id}/stream`, {
        headers: headers({ Accept: "text/event-stream" }),
        cache: "no-store",
        signal: controller.signal,
      });
      if (!r.ok || !r.body) throw new Error(`实时事件接口返回 ${r.status}`);
      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        buffer += decoder.decode(value, { stream: !done });
        const blocks = buffer.split("\n\n");
        buffer = blocks.pop() || "";
        for (const block of blocks) {
          const eventName = block
            .split("\n")
            .find((line) => line.startsWith("event:"))
            ?.slice(6)
            .trim();
          const raw = block
            .split("\n")
            .find((line) => line.startsWith("data:"))
            ?.slice(5)
            .trim();
          if (raw && eventName !== "close") {
            const event = JSON.parse(raw) as EventRecord;
            setEvents((current) =>
              current.some((x) => x.sequence === event.sequence)
                ? current
                : [...current, event],
            );
            await syncExperiment();
          }
          if (eventName === "close") {
            await syncExperiment();
            await refresh();
            return;
          }
        }
        if (done) return;
      }
    };
    void stream().catch((e) => {
      if (!controller.signal.aborted)
        setError(e instanceof Error ? e.message : String(e));
    });
    return () => controller.abort();
  }, [drawer?.id]);
  const filtered = useMemo(
    () =>
      data.experiments.filter((x) =>
        `${x.name} ${x.sample} ${x.status}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [data.experiments, query],
  );
  const connected = !error && data.mode === "connected";
  const title = NAV.find((x) => x.id === view)?.label || "态势总览";
  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <div className="brandMark">
            <Activity size={18} />
          </div>
          <div>
            <strong>逆向分析平台</strong>
            <span>证据驱动控制台</span>
          </div>
        </div>
        <div className="workspaceBox">
          <CircleDot size={13} />
          <span>{connected ? data.workspace : "未连接工作区"}</span>
        </div>
        <nav className="nav">
          {NAV.map(({ id, label, hint, icon: Icon }) => (
            <button
              key={id}
              className={view === id ? "active" : ""}
              onClick={() => setView(id)}
              disabled={(id === "access" || id === "providers") && identity?.role !== "admin"}
            >
              <Icon size={17} />
              <span>
                <b>{label}</b>
                <small>{hint}</small>
              </span>
              <ChevronRight size={14} />
            </button>
          ))}
        </nav>
        <div className="railFoot">
          <span>数据模式</span>
          <b>{connected ? "真实工作区" : "离线"}</b>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div>
            <p>逆向分析平台网页端</p>
            <h1>{title}</h1>
          </div>
          <div className="topActions">
            <input
              className="tokenInput"
              value={token}
              onChange={(e) => {
                setToken(e.target.value);
                localStorage.setItem("reverseAnalyzerWebToken", e.target.value);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") void refresh();
              }}
              placeholder="输入访问令牌后按回车键"
              aria-label="访问令牌"
            />
            <div className={`liveBadge ${connected ? "ok" : "warn"}`}>
              <span />
              {loading ? "读取中" : connected ? "接口已连接" : "接口异常"}
            </div>
            <button
              className="iconBtn"
              onClick={() => void refresh()}
              title="重新连接"
            >
              <RefreshCw size={17} />
            </button>
            <button
              className="primaryBtn"
              onClick={() => setCreateOpen(true)}
              disabled={!connected || identity?.role === "viewer"}
            >
              <HardDriveUpload size={16} />
              新建任务
            </button>
          </div>
        </header>
        <section className="content">
          {error && <Banner text={`无法读取真实数据：${error}`} />}{" "}
          {view === "overview" && <Overview data={data} onOpen={setView} />}{" "}
          {view === "experiments" && (
            <Experiments
              items={filtered}
              query={query}
              setQuery={setQuery}
              onSelect={setDrawer}
              onCreate={() => {
                setCatalogAsset(null);
                setCreateOpen(true);
              }}
            />
          )}{" "}
          {view === "catalog" && (
            <Catalog
              items={catalog}
              loading={catalogLoading}
              onUse={(item) => {
                setCatalogAsset(item);
                setCreateOpen(true);
              }}
            />
          )}{" "}
          {view === "providers" && identity?.role === "admin" && (
            <ProvidersView
              data={providers}
              loading={providersLoading}
              onChanged={refreshProviders}
            />
          )}{" "}
          {view === "environment" && <Environment data={data.environment} />}{" "}
          {view === "knowledge" && (
            <KnowledgeView data={data.knowledge} onChanged={refresh} />
          )}{" "}
          {view === "access" && identity?.role === "admin" && <AccessControl workspace={data.workspace} />}
          {(view === "providers" || view === "access") &&
            identity?.role !== "admin" && (
              <Banner text="当前账号无权访问管理功能" />
            )}
        </section>
      </main>
      {createOpen && identity?.role !== "viewer" && (
        <CreateDialog
          asset={catalogAsset}
          onClose={() => {
            setCreateOpen(false);
            setCatalogAsset(null);
          }}
          onCreated={async (x) => {
            setCreateOpen(false);
            setCatalogAsset(null);
            await refresh();
            setView("experiments");
            setDrawer(x);
          }}
        />
      )}
      {drawer && (
        <FlowDrawer
          experiment={drawer}
          events={events}
          identity={identity}
          onClose={() => setDrawer(null)}
          onChanged={refresh}
        />
      )}
    </div>
  );
}

function Overview({
  data,
  onOpen,
}: {
  data: Workspace;
  onOpen: (v: View) => void;
}) {
  const s = data.summary;
  return (
    <>
      <div className="metricGrid">
        <Metric
          label="任务总数"
          value={Number(s.experiment_total || 0)}
          detail={`${Number(s.active_total || 0)} 个活动任务`}
          icon={FileSearch}
          tone="cyan"
        />
        <Metric
          label="能力就绪率"
          value={`${Number(s.capability_readiness || 0)}%`}
          detail="基于能力矩阵"
          icon={Gauge}
          tone="green"
        />
        <Metric
          label="依赖受限"
          value={Number(s.toolchain_dependency_gated || 0)}
          detail="工具链或设备门禁"
          icon={AlertTriangle}
          tone="amber"
        />
        <Metric
          label="知识条目"
          value={Number(s.knowledge_total || 0)}
          detail="可召回经验与策略"
          icon={Database}
          tone="violet"
        />
      </div>
      <Panel
        title="最近流程"
        action="打开工作台"
        onAction={() => onOpen("experiments")}
      >
        <ExperimentTable items={data.experiments.slice(0, 8)} />
      </Panel>
    </>
  );
}
function Experiments({
  items,
  query,
  setQuery,
  onSelect,
  onCreate,
}: {
  items: Experiment[];
  query: string;
  setQuery: (s: string) => void;
  onSelect: (x: Experiment) => void;
  onCreate: () => void;
}) {
  return (
    <Panel title="流程工作台" wide>
      <Toolbar query={query} setQuery={setQuery}>
        <button className="primaryBtn" onClick={onCreate}>
          <HardDriveUpload size={16} />
          上传或选择样本
        </button>
      </Toolbar>
      <ExperimentTable items={items} onSelect={onSelect} />
    </Panel>
  );
}
function ExperimentTable({
  items,
  onSelect,
}: {
  items: Experiment[];
  onSelect?: (x: Experiment) => void;
}) {
  if (!items.length) return <Empty text="当前没有任务记录" />;
  return (
    <div className="table">
      {items.map((x) => (
        <button className="tableRow" key={x.id} onClick={() => onSelect?.(x)}>
          <span>
            <FileSearch size={17} />
            <b>{x.name || "未命名任务"}</b>
            <small>{x.sample}</small>
          </span>
          <span className={`pill ${tone(x.status)}`}>{status(x.status)}</span>
          <code>{Object.keys(x.options || {}).join(", ") || "默认"}</code>
          <small>{date(x.updated_at)}</small>
        </button>
      ))}
    </div>
  );
}

function Catalog({
  items,
  loading,
  onUse,
}: {
  items: CatalogItem[];
  loading: boolean;
  onUse: (item: CatalogItem) => void;
}) {
  const kinds: CatalogKind[] = [
    "skill",
    "tool",
    "capability",
    "script",
    "dependency",
  ];
  const names: Record<CatalogKind, string> = {
    skill: "技能",
    tool: "工具",
    capability: "能力",
    script: "脚本",
    dependency: "依赖",
  };
  const [active, setActive] = useState<CatalogKind | "all">("all");
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<CatalogItem | null>(null);
  const visible = useMemo(
    () =>
      items.filter(
        (item) =>
          (active === "all" || item.kind === active) &&
          `${item.name} ${item.id} ${item.description} ${item.source} ${item.routes.join(" ")}`
            .toLowerCase()
            .includes(filter.trim().toLowerCase()),
      ),
    [items, active, filter],
  );
  return (
    <>
      <div className="catalogMetrics">
        {kinds.map((k) => (
          <button
            className={`catalogMetric ${active === k ? "active" : ""}`}
            key={k}
            onClick={() => setActive(active === k ? "all" : k)}
          >
            <span>{names[k]}</span>
            <strong>{items.filter((x) => x.kind === k).length}</strong>
          </button>
        ))}
      </div>
      <Panel title="平台资产目录" wide>
        <div className="catalogToolbar">
          <div className="search">
            <Search size={16} />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="搜索名称、路由、模块或说明"
            />
          </div>
          <div className="catalogTabs">
            <button
              className={active === "all" ? "active" : ""}
              onClick={() => setActive("all")}
            >
              全部 <b>{items.length}</b>
            </button>
            {kinds.map((k) => (
              <button
                className={active === k ? "active" : ""}
                key={k}
                onClick={() => setActive(k)}
              >
                {names[k]} <b>{items.filter((x) => x.kind === k).length}</b>
              </button>
            ))}
          </div>
        </div>
        {loading ? (
          <div className="catalogState">
            <Loader2 className="spin" />
            正在读取真实目录
          </div>
        ) : !visible.length ? (
          <Empty text="没有匹配的目录项" />
        ) : (
          <div className="catalogList compactCatalog">
            {visible.map((x) => (
              <button
                className="catalogRow"
                key={`${x.kind}:${x.id}`}
                onClick={() => setSelected(x)}
              >
                <div className="catalogIdentity">
                  <span>{names[x.kind]}</span>
                  <div>
                    <h4>{x.name}</h4>
                    <p>{x.description || x.id}</p>
                    <code>
                      {x.source ||
                        x.callable_name ||
                        x.execution_boundary ||
                        "未标注来源"}
                    </code>
                  </div>
                </div>
                <div className="catalogStates">
                  <span className={x.registered ? "ok" : "gap"}>
                    {x.registered ? "已注册" : "未注册"}
                  </span>
                  <span className={x.callable ? "ok" : "gap"}>
                    {x.callable ? "有调用入口" : "无调用入口"}
                  </span>
                  <span className={x.dependency_ready ? "ok" : "neutral"}>
                    {x.dependency_ready ? "依赖就绪" : "依赖未验证"}
                  </span>
                  <span className={x.accepted ? "ok" : "neutral"}>
                    {x.accepted ? "真实验收" : "尚未验收"}
                  </span>
                </div>
                <ChevronRight size={16} />
              </button>
            ))}
          </div>
        )}
      </Panel>
      {selected && (
        <div className="modalLayer">
          <button className="scrim" onClick={() => setSelected(null)} />
          <section className="catalogDetail">
            <header>
              <div>
                <p>{names[selected.kind]}详情</p>
                <h2>{selected.name}</h2>
              </div>
              <button
                className="iconBtn"
                onClick={() => setSelected(null)}
                title="关闭"
              >
                <X size={17} />
              </button>
            </header>
            <div className="catalogDetailBody">
              <code>{selected.id}</code>
              <p>{selected.description || "该目录项尚未提供说明。"}</p>
              <dl>
                <dt>来源</dt>
                <dd>{selected.source || "未标注"}</dd>
                <dt>执行边界</dt>
                <dd>{selected.execution_boundary || "未声明"}</dd>
                <dt>调用入口</dt>
                <dd>
                  {selected.callable_name ||
                    (selected.callable ? "已注册" : "无")}
                </dd>
                <dt>路由</dt>
                <dd>{selected.routes.join("、") || "通用"}</dd>
                <dt>缺少依赖</dt>
                <dd>
                  {selected.missing_dependencies.join("、") || "目录未报告"}
                </dd>
                <dt>验收命令</dt>
                <dd>{selected.acceptance_command || "尚未绑定"}</dd>
              </dl>
            </div>
            <footer>
              <button className="ghostBtn" onClick={() => setSelected(null)}>
                关闭
              </button>
              {selected.kind !== "dependency" && (
                <button
                  className="primaryBtn"
                  onClick={() => {
                    setSelected(null);
                    onUse(selected);
                  }}
                >
                  <Play size={15} />
                  用于新任务
                </button>
              )}
            </footer>
          </section>
        </div>
      )}
    </>
  );
}

function ProvidersView({
  data,
  loading,
  onChanged,
}: {
  data: Provider[];
  loading: boolean;
  onChanged: () => Promise<void>;
}) {
  const [selected, setSelected] = useState<Provider | null>(null);
  const [apiKeys, setApiKeys] = useState("");
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (!selected && data.length) setSelected(data[0]);
  }, [data, selected]);
  const save = async () => {
    if (!selected) return;
    setMessage("保存中");
    const profile = apiKeys.trim()
      ? { ...selected, api_keys: apiKeys.split(/\r?\n/).map((key) => key.trim()).filter(Boolean) }
      : selected;
    const r = await fetch("/api/providers", {
      method: "PUT",
      headers: headers({ "Content-Type": "application/json" }),
      body: JSON.stringify(profile),
    });
    const p = await r.json();
    setMessage(r.ok ? "配置已保存" : p.error || "保存失败");
    if (r.ok) await onChanged();
  };
  const test = async () => {
    if (!selected) return;
    setMessage("连接测试中");
    const r = await fetch("/api/providers/test", {
      method: "POST",
      headers: headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ name: selected.name, profile: selected }),
    });
    const p = await r.json();
    setMessage(
      r.ok
        ? `连接成功：${p.model || selected.model || "本地服务"} · 密钥槽位 ${p.key_slot || "无需密钥"}`
        : `连接失败：${p.error || r.status}`,
    );
    await onChanged();
  };
  return (
    <div className="knowledgeLayout">
      <Panel title="模型服务列表">
        {loading ? (
          <div className="catalogState">
            <Loader2 className="spin" />
            读取配置
          </div>
        ) : (
          <div className="capabilityList">
            {data.map((x) => (
              <button
                className="capabilityRow"
                key={x.name}
                onClick={() => {
                  setSelected({ ...x });
                  setApiKeys("");
                  setMessage("");
                }}
              >
                <Zap size={18} />
                <div>
                  <div className="rowTitle">
                    <h3>{x.name}</h3>
                    <span className={`pill ${x.enabled ? "done" : "queued"}`}>
                      {x.enabled ? "已启用" : "已停用"}
                    </span>
                  </div>
                  <p>
                    {x.kind} · {x.model || "本地规则引擎"}
                  </p>
                  <code>
                    优先级 {x.priority} · 请求{" "}
                    {x.usage?.Requests ?? x.usage?.requests ?? 0} · 失败{" "}
                    {x.usage?.Failures ?? x.usage?.failures ?? 0}
                  </code>
                </div>
              </button>
            ))}
          </div>
        )}
      </Panel>
      <Panel title="模型服务配置">
        {selected ? (
          <div className="formStack">
            <label>
              名称
              <input
                value={selected.name}
                disabled={selected.name === "rule_based"}
                onChange={(e) =>
                  setSelected({ ...selected, name: e.target.value })
                }
              />
            </label>
            <label>
              类型
              <select
                value={selected.kind}
                disabled={selected.name === "rule_based"}
                onChange={(e) =>
                  setSelected({ ...selected, kind: e.target.value })
                }
              >
                <option value="local">本地</option>
                <option value="openai-compatible">开放模型接口兼容模式</option>
              </select>
            </label>
            <div className="modelPriorityEditor">
              <div className="fieldHeader">
                <span>模型优先级</span>
                <button
                  className="iconBtn"
                  title="添加模型"
                  onClick={() => {
                    const models = [...(selected.models || [])];
                    models.push({ id: "", display_name: "", priority: (models.length + 1) * 10, enabled: true });
                    setSelected({ ...selected, models });
                  }}
                >
                  <Plus size={15} />
                </button>
              </div>
              {(selected.models?.length ? selected.models : [{ id: selected.model || "", display_name: selected.model || "", priority: 10, enabled: true }]).map((model, index, source) => (
                <div className="modelPriorityRow" key={`${index}-${model.id}`}>
                  <span className="priorityIndex">{index + 1}</span>
                  <input
                    aria-label={`第 ${index + 1} 优先模型`}
                    value={model.id}
                    placeholder="模型 ID"
                    onChange={(e) => {
                      const models = [...source];
                      models[index] = { ...model, id: e.target.value, priority: (index + 1) * 10 };
                      setSelected({ ...selected, model: index === 0 ? e.target.value : selected.model, models });
                    }}
                  />
                  <button className="iconBtn" title="上移" disabled={index === 0} onClick={() => {
                    const models = [...source]; [models[index - 1], models[index]] = [models[index], models[index - 1]];
                    models.forEach((item, i) => { item.priority = (i + 1) * 10; });
                    setSelected({ ...selected, model: models[0].id, models });
                  }}><ChevronUp size={15} /></button>
                  <button className="iconBtn" title="下移" disabled={index === source.length - 1} onClick={() => {
                    const models = [...source]; [models[index + 1], models[index]] = [models[index], models[index + 1]];
                    models.forEach((item, i) => { item.priority = (i + 1) * 10; });
                    setSelected({ ...selected, model: models[0].id, models });
                  }}><ChevronDown size={15} /></button>
                  <button className="iconBtn danger" title="删除模型" disabled={source.length === 1} onClick={() => {
                    const models = source.filter((_, i) => i !== index).map((item, i) => ({ ...item, priority: (i + 1) * 10 }));
                    setSelected({ ...selected, model: models[0]?.id || "", models });
                  }}><Trash2 size={15} /></button>
                </div>
              ))}
            </div>
            <label>
              接口协议
              <select
                value={selected.protocol || (selected.model?.startsWith("gpt-") ? "responses" : "chat_completions")}
                disabled={selected.kind === "local"}
                onChange={(e) =>
                  setSelected({ ...selected, protocol: e.target.value as Provider["protocol"] })
                }
              >
                <option value="responses">OpenAI 原生 Responses（/v1/responses）</option>
                <option value="chat_completions">Chat Completions（/v1/chat/completions）</option>
              </select>
            </label>
            <label>
              服务端点
              <input
                value={selected.base_url || ""}
                disabled={selected.kind === "local"}
                onChange={(e) =>
                  setSelected({ ...selected, base_url: e.target.value })
                }
              />
            </label>
            <label>
              API Key（每行一个，第一行优先）
              <textarea
                value={apiKeys}
                disabled={selected.kind === "local"}
                onChange={(e) =>
                  setApiKeys(e.target.value)
                }
                placeholder={selected.key_count ? `已配置 ${selected.key_count} 个 Key；粘贴完整列表以更新` : "每行粘贴一个 API Key"}
              />
            </label>
            {selected.kind !== "local" && (
              <div className="modelPriorityEditor">
                <div className="fieldHeader">
                  <span>API Key 优先级</span>
                  <small>{apiKeys.trim() ? "待保存" : `已配置 ${selected.key_count || 0} 个`}</small>
                </div>
                {Array.from({
                  length: apiKeys.trim()
                    ? apiKeys.split(/\r?\n/).map((key) => key.trim()).filter(Boolean).length
                    : selected.key_count || 0,
                }).map((_, index) => (
                  <div className="modelPriorityRow" key={`key-slot-${index + 1}`}>
                    <span className="priorityIndex">{index + 1}</span>
                    <input
                      aria-label={`API Key 槽位 ${index + 1}`}
                      value={`密钥槽位 ${index + 1}`}
                      readOnly
                    />
                    <span className="pill done">已配置</span>
                  </div>
                ))}
              </div>
            )}
            <label>
              优先级
              <input
                type="number"
                value={selected.priority}
                onChange={(e) =>
                  setSelected({ ...selected, priority: Number(e.target.value) })
                }
              />
            </label>
            <label>
              <input
                type="checkbox"
                checked={selected.enabled}
                disabled={selected.name === "rule_based"}
                onChange={(e) =>
                  setSelected({ ...selected, enabled: e.target.checked })
                }
              />
              启用此模型服务
            </label>
            {message && <div className="inlineMsg">{message}</div>}
            <div className="actionRow">
              <button className="primaryBtn" onClick={() => void save()}>
                <Database size={15} />
                保存配置
              </button>
              <button className="ghostBtn" onClick={() => void test()}>
                <Zap size={15} />
                连接测试
              </button>
            </div>
          </div>
        ) : (
          <Empty text="请选择模型服务" />
        )}
      </Panel>
    </div>
  );
}

function Environment({ data }: { data?: EnvironmentPayload }) {
  if (!data)
    return (
      <Panel title="环境验收">
        <Empty text="暂无环境数据" />
      </Panel>
    );
  return (
    <Panel title="运行环境与真实验收" wide>
      <div className="metricGrid">
        <Metric
          label="已验证工具链"
          value={data.summary.verified || 0}
          detail="仅表示探针通过"
          icon={ShieldCheck}
          tone="green"
        />
        <Metric
          label="依赖受限"
          value={data.summary.dependency_gated || 0}
          detail="缺少工具、设备或配置"
          icon={AlertTriangle}
          tone="amber"
        />
        <Metric
          label="可运行验收"
          value={data.summary.acceptance_fixture_ready_to_run || 0}
          detail="仍需执行真实 fixture"
          icon={Play}
          tone="violet"
        />
        <Metric
          label="沙箱状态"
          value={String(data.sandbox?.status || "未知")}
          detail={(String(data.storage?.backend || "json") === "json" ? "文件" : String(data.storage?.backend)) + " 存储"}
          icon={Terminal}
          tone="cyan"
        />
      </div>
      <div className="environmentGrid">
        <section>
          <h3>工具链工作流</h3>
          <div className="capabilityList">
            {data.workflows.map((x) => (
              <article className="capabilityRow" key={x.id}>
                <Terminal size={18} />
                <div>
                  <div className="rowTitle">
                    <h3>{x.id}</h3>
                    <span className={`pill ${tone(x.status)}`}>
                      {status(x.status)}
                    </span>
                  </div>
                  <p>{x.note || "暂无说明"}</p>
                  <code>
                    {x.missing?.length
                      ? `缺少：${x.missing.join(", ")}`
                      : "依赖探测通过"}
                  </code>
                </div>
              </article>
            ))}
          </div>
        </section>
        <section>
          <h3>真实目标验收</h3>
          <div className="capabilityList">
            {data.acceptance_fixtures.map((x) => (
              <article className="capabilityRow" key={x.id}>
                <ShieldCheck size={18} />
                <div>
                  <div className="rowTitle">
                    <h3>{x.id}</h3>
                    <span className={`pill ${tone(x.status)}`}>
                      {status(x.status)}
                    </span>
                  </div>
                  <p>{x.capability}</p>
                  <code>
                    {x.missing_gates?.length
                      ? `缺少门禁：${x.missing_gates.join(", ")}`
                      : x.command}
                  </code>
                </div>
                <b>{x.phase}</b>
              </article>
            ))}
          </div>
        </section>
      </div>
    </Panel>
  );
}

function KnowledgeView({
  data,
  onChanged,
}: {
  data: Knowledge[];
  onChanged: () => Promise<void>;
}) {
  const [draft, setDraft] = useState({ title: "", content: "", tags: "" });
  const submit = async () => {
    const r = await fetch("/api/knowledge", {
      method: "POST",
      headers: headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        ...draft,
        tags: draft.tags.split(/[,，\s]+/).filter(Boolean),
        type: "guide",
      }),
    });
    if (r.ok) {
      setDraft({ title: "", content: "", tags: "" });
      await onChanged();
    }
  };
  return (
    <div className="knowledgeLayout">
      <Panel title="知识条目">
        <div className="knowledgeList">
          {data.map((x) => (
            <article className="knowledgeItem" key={x.id}>
              <span>{x.type === "guide" ? "指南" : x.type === "memory" || !x.type ? "记忆" : x.type}</span>
              <h3>{x.title || "未命名知识"}</h3>
              <p>{x.content}</p>
              <small>
                {x.tags?.join(" / ") || "无标签"} · {date(x.updated_at)}
              </small>
            </article>
          ))}
        </div>
        {!data.length && <Empty text="暂无知识条目" />}
      </Panel>
      <Panel title="新增知识">
        <div className="formStack">
          <label>
            标题
            <input
              value={draft.title}
              onChange={(e) => setDraft({ ...draft, title: e.target.value })}
            />
          </label>
          <label>
            标签
            <input
              value={draft.tags}
              onChange={(e) => setDraft({ ...draft, tags: e.target.value })}
            />
          </label>
          <label>
            内容
            <textarea
              rows={9}
              value={draft.content}
              onChange={(e) => setDraft({ ...draft, content: e.target.value })}
            />
          </label>
          <button
            className="primaryBtn"
            disabled={!draft.content.trim()}
            onClick={() => void submit()}
          >
            <BookOpen size={16} />
            写入知识库
          </button>
        </div>
      </Panel>
    </div>
  );
}

function AccessControl({ workspace }: { workspace: string }) {
  type TokenItem = {
    id: string;
    subject: string;
    role: string;
    workspace: string;
    created_at?: string;
    expires_at?: string;
    revoked: boolean;
  };
  const [items, setItems] = useState<TokenItem[]>([]);
  const [draft, setDraft] = useState({
    subject: "",
    role: "analyst",
    workspace,
  });
  const [issuedToken, setIssuedToken] = useState("");
  const [message, setMessage] = useState("");
  const load = async () => {
    const r = await fetch("/api/auth/tokens", {
      headers: headers(),
      cache: "no-store",
    });
    const p = await r.json();
    if (r.ok) setItems(p.tokens || []);
    else setMessage(p.error || "无法读取令牌");
  };
  useEffect(() => {
    void load();
  }, []);
  useEffect(
    () => setDraft((current) => ({ ...current, workspace })),
    [workspace],
  );
  const create = async () => {
    const r = await fetch("/api/auth/tokens", {
      method: "POST",
      headers: headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        Subject: draft.subject,
        Role: draft.role,
      }),
    });
    const p = await r.json();
    setMessage(r.ok ? "令牌已创建，请妥善保管原始值" : p.error || "创建失败");
    if (r.ok) {
      setIssuedToken(p.token || "");
      setDraft({ ...draft, subject: "" });
      await load();
    }
  };
  const revoke = async (id: string) => {
    const r = await fetch(`/api/auth/tokens/${id}`, {
      method: "DELETE",
      headers: headers(),
    });
    setMessage(r.ok ? "令牌已撤销" : "撤销失败");
    if (r.ok) await load();
  };
  return (
    <div className="knowledgeLayout">
      <Panel title="接口令牌">
        <div className="capabilityList">
          {items.map((item) => (
            <article className="capabilityRow" key={item.id}>
              <ShieldCheck size={18} />
              <div>
                <div className="rowTitle">
                  <h3>{item.subject}</h3>
                  <span className={`pill ${item.revoked ? "missing" : "done"}`}>
                    {item.revoked ? "已撤销" : item.role}
                  </span>
                </div>
                <p>{item.workspace}</p>
                <code>
                  {item.id} · {date(item.created_at)}
                </code>
              </div>
              {!item.revoked && (
                <button
                  className="ghostBtn"
                  onClick={() => void revoke(item.id)}
                >
                  撤销
                </button>
              )}
            </article>
          ))}
        </div>
        {!items.length && <Empty text="当前没有可管理的令牌" />}
      </Panel>
      <Panel title="签发令牌">
        <div className="formStack">
          <label>
            主体
            <input
              value={draft.subject}
              onChange={(e) => setDraft({ ...draft, subject: e.target.value })}
              placeholder="分析人员标识"
            />
          </label>
          <label>
            角色
            <select
              value={draft.role}
              onChange={(e) => setDraft({ ...draft, role: e.target.value })}
            >
              <option value="viewer">只读查看者</option>
              <option value="analyst">分析人员</option>
              <option value="admin">管理员</option>
            </select>
          </label>
          <label>
            工作区
            <input
              value={draft.workspace}
              readOnly
            />
          </label>
          <label>
            原始令牌
            <input
              type="text"
              value={issuedToken}
              readOnly
              placeholder="仅以 SHA-256 保存"
            />
          </label>
          {message && <div className="inlineMsg">{message}</div>}
          <button
            className="primaryBtn"
            disabled={!draft.subject}
            onClick={() => void create()}
          >
            <ShieldCheck size={16} />
            签发令牌
          </button>
        </div>
      </Panel>
    </div>
  );
}

function CreateDialog({
  asset,
  onClose,
  onCreated,
}: {
  asset?: CatalogItem | null;
  onClose: () => void;
  onCreated: (x: Experiment) => Promise<void>;
}) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState(
    asset?.routes.includes("gui")
      ? "gui-evidence"
      : asset?.name.toLowerCase().includes("ghidra")
        ? "pe-reconstruction"
        : "evidence-first",
  );
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const upload = async (file: File) => {
    setBusy(true);
    setMessage(`正在上传 ${file.name}`);
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      const r = await fetch("/api/uploads", {
        method: "POST",
        headers: headers(),
        body: form,
      });
      const p = await r.json();
      if (r.ok) {
        setTarget(p.path);
        if (/\.(zip|exe|dll|apk|ipa)$/i.test(file.name)) {
          setMode("pe-reconstruction");
        }
        setMessage(
          `上传完成：${file.name}（${Math.ceil(Number(p.size || file.size) / 1024 / 1024)} 兆字节）`,
        );
      } else setMessage(p.error || "上传失败");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "上传失败");
    } finally {
      setBusy(false);
    }
  };
  const create = async () => {
    if (/^[A-Za-z]:[\\/]/.test(target)) {
      setMessage(
        "容器无法读取宿主机盘符路径，请点击上方“选择本地样本”完成上传",
      );
      return;
    }
    setBusy(true);
    const r = await fetch("/api/experiments", {
      method: "POST",
      headers: headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ target, mode, requested_asset: asset?.id || "" }),
    });
    const p = await r.json();
    setBusy(false);
    if (r.ok) await onCreated(p.experiment);
    else setMessage(p.error || "创建失败");
  };
  return (
    <div className="modalLayer">
      <button className="scrim" onClick={onClose} />
      <section className="modal">
        <header>
          <div>
            <p>新建流程</p>
            <h2>上传样本或选择工作区文件</h2>
          </div>
          <button className="iconBtn" onClick={onClose}>
            <X size={17} />
          </button>
        </header>
        {asset && (
          <div className="selectedAsset">
            <Boxes size={17} />
            <div>
              <span>本次任务调用</span>
              <b>{asset.name}</b>
              <code>{asset.callable_name || asset.id}</code>
            </div>
          </div>
        )}
        <label className="dropZone">
          <HardDriveUpload size={24} />
          <b>{busy ? "正在上传，请稍候" : "选择本地样本"}</b>
          <span>支持最大 512 兆字节；文件写入上传目录，不会自动执行</span>
          <input
            type="file"
            disabled={busy}
            onChange={(e) =>
              e.target.files?.[0] && void upload(e.target.files[0])
            }
          />
        </label>
        <label>
          目标路径
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="上传后自动生成，无需填写宿主机盘符路径"
          />
        </label>
        <label>
          分析模式
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="evidence-first">证据优先</option>
            <option value="pe-reconstruction">可执行文件深度分析与源码还原</option>
            <option value="protocol-review">协议捕获审查</option>
            <option value="gui-evidence">图形界面证据流水线</option>
          </select>
        </label>
        {message && <div className="inlineMsg">{message}</div>}
        <footer>
          <button className="ghostBtn" onClick={onClose}>
            取消
          </button>
          <button
            className="primaryBtn"
            disabled={busy || !target}
            onClick={() => void create()}
          >
            {busy ? <Loader2 className="spin" /> : <Play size={16} />}创建计划
          </button>
        </footer>
      </section>
    </div>
  );
}

function FlowDrawer({
  experiment,
  events,
  identity,
  onClose,
  onChanged,
}: {
  experiment: Experiment;
  events: EventRecord[];
  identity: Identity;
  onClose: () => void;
  onChanged: () => Promise<void>;
}) {
  const canWrite = ["admin", "analyst"].includes(identity?.role || "");
  const [busy, setBusy] = useState("");
  const [logMode, setLogMode] = useState<"events" | "raw">("events");
  const [sourceOpen, setSourceOpen] = useState(false);
  const [patchOpen, setPatchOpen] = useState(false);
  const [previewPath, setPreviewPath] = useState("");
  const [actionMessage, setActionMessage] = useState("");
  const [, setClock] = useState(0);
  useEffect(() => {
    if (experiment.status !== "running") return;
    const timer = setInterval(() => setClock((x) => x + 1), 1000);
    return () => clearInterval(timer);
  }, [experiment.status]);
  const action = async (name: "execute" | "cancel" | "retry") => {
    if (!canWrite) {
      setActionMessage("只读角色不能执行、取消或重试任务。");
      return;
    }
    if (
      name === "execute" &&
      !confirm("确认执行此任务流程？任务将在隔离环境中调用已配置的工具和模型。")
    )
      return;
    if (
      name === "retry" &&
      !confirm(
        "确认从头重试整个任务流程？现有证据会保留，不会从失败轮次中间续跑。",
      )
    )
      return;
    setBusy(name);
    setActionMessage("");
    try {
      const response = await fetch(
        `/api/experiments/${experiment.id}/${name}`,
        {
          method: "POST",
          headers: headers({ "Content-Type": "application/json" }),
          body:
            name === "execute"
              ? JSON.stringify({ confirmation: CONFIRMATION })
              : "{}",
        },
      );
      const payload = await response.json();
      if (!response.ok)
        throw new Error(payload.error || `操作失败：${response.status}`);
      setActionMessage(
        name === "retry"
          ? "已创建全新的重试任务"
          : name === "execute"
            ? "人工确认已记录，任务开始执行"
            : "任务已取消",
      );
      await onChanged();
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy("");
    }
  };
  const outputEvents = events.filter((x) => x.type === "output");
  const progressEvents = events.filter((x) => x.type === "progress");
  const summaryEvents = events.filter((x) => x.type === "result_summary");
  const keyEvents = events.filter(
    (x) =>
      x.type !== "output" &&
      x.type !== "progress" &&
      x.type !== "result_summary",
  );
  const legacySuppressed = Math.max(
    0,
    events.reduce((maximum, event) => Math.max(maximum, event.sequence), 0) -
      events.length,
  );
  const outputLineCount = Number(
    summaryEvents[summaryEvents.length - 1]?.data?.output_lines ||
      outputEvents.length ||
      legacySuppressed,
  );
  const outputSummary = summaryEvents.length
    ? summaryEvents
        .map((x) => `${x.message}\n${JSON.stringify(x.data || {}, null, 2)}`)
        .join("\n\n")
    : legacySuppressed
      ? `旧版本任务的 ${legacySuppressed} 条逐行原始输出已折叠。\n这些内容仍保留在任务事件文件中，但不再加载到浏览器。`
      : "分析结束后将显示输出规模和归档路径。";
  const reportedProgress = Number(
    progressEvents[progressEvents.length - 1]?.data?.percent || 0,
  );
  const progress = flowProgress(
    experiment.status,
    outputEvents.length,
    reportedProgress,
  );
  const stages = [
    { key: "queued", label: "排队" },
    { key: "planned", label: "计划" },
    { key: "running", label: "分析" },
    { key: "completed", label: "完成" },
  ];
  const stageIndex =
    experiment.status === "failed" || experiment.status === "cancelled"
      ? 2
      : experiment.status === "partial"
        ? 3
      : Math.max(
          0,
          stages.findIndex((x) => x.key === experiment.status),
        );
  const latest =
    experiment.status === "running"
      ? progressEvents[progressEvents.length - 1]?.message || "分析引擎运行中"
      : keyEvents[keyEvents.length - 1]?.message || status(experiment.status);
  const hasSourceProject = (experiment.artifacts || []).some((item) =>
    String(item.path || "").endsWith("/CMakeLists.txt"),
  );
  const artifactSummary =
    experiment.summary && typeof experiment.summary === "object"
      ? (experiment.summary as Record<string, unknown>)
      : {};
  const artifactBytes = Number(artifactSummary.artifact_total_bytes || 0);
  const packageBytes = Number(artifactSummary.package_bytes || 0);
  const artifactFiles = Number(
    artifactSummary.artifact_file_count || experiment.artifacts?.length || 0,
  );
  const reconstruction = experiment.reconstruction;
  const reconstructionGates = reconstruction
    ? ([
        ["分析完成", reconstruction.analysis_complete],
        ["源码生成", reconstruction.source_generated],
        ["结构完整", reconstruction.structure_complete],
        ["依赖锁定", reconstruction.dependencies_locked],
        ["真实构建", reconstruction.build_passed],
        ["行为验证", reconstruction.behavior_passed],
      ] as Array<[string, boolean]>)
    : [];
  const modelState = (experiment.metadata?.model_reconstruction ||
    null) as Record<string, unknown> | null;
  const buildState = (experiment.metadata?.automated_build || null) as Record<
    string,
    unknown
  > | null;
  const behaviorState = (experiment.metadata?.behavior_validation ||
    null) as Record<string, unknown> | null;
  const buildRepair = (experiment.metadata?.build_repair_loop ||
    null) as Record<string, unknown> | null;
  const behaviorRepair = (experiment.metadata?.behavior_repair_loop ||
    null) as Record<string, unknown> | null;
  const confirmationEvent = events.find(
    (x) => x.type === "execution_confirmed",
  );
  const retryNeeded = [buildRepair, behaviorRepair].some(
    (x) =>
      x &&
      ["dependency-gated", "exhausted", "failed"].includes(
        String(x.status || ""),
      ),
  );
  return (
    <>
      <aside className="drawer">
        <header>
          <div>
            <p>流程详情</p>
            <h2>{experiment.name || experiment.id}</h2>
          </div>
          <button className="iconBtn" onClick={onClose} title="关闭">
            <X size={17} />
          </button>
        </header>
        <div className="drawerMeta">
          <span className={`pill ${tone(experiment.status)}`}>
            {status(experiment.status)}
          </span>
          <code>{experiment.id}</code>
          <small>{experiment.sample}</small>
        </div>
        <section
          className={`progressOverview ${experiment.status === "failed" ? "failed" : ""}`}
        >
          <div className="progressHeading">
            <div>
              <span>
                {experiment.status === "running"
                  ? "处理进度（估算）"
                  : "任务进度"}
              </span>
              <strong>{progress}%</strong>
            </div>
            <small>
              {experiment.status === "running"
                ? `分析引擎活动中 · 已运行 ${elapsed(experiment.created_at)}`
                : status(experiment.status)}
            </small>
          </div>
          <div
            className="progressTrack"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress}
          >
            <span style={{ width: `${progress}%` }} />
          </div>
          <p title={latest}>{latest}</p>
        </section>
        {experiment.status === "failed" && experiment.error && (
          <section className="failureDiagnostics">
            <div>
              <AlertTriangle size={15} />
              <b>分析进程退出原因</b>
            </div>
            <pre>{experiment.error}</pre>
          </section>
        )}
        <div className="stageFlow">
          {stages.map((stage, i) => (
            <div
              className={`stageNode ${i < stageIndex ? "complete" : i === stageIndex ? "current" : ""}`}
              key={stage.key}
            >
              <span className="stageDot" />
              <div>
                <b>{stage.label}</b>
                <small>
                  {i < stageIndex
                    ? "已完成"
                    : i === stageIndex
                      ? "当前阶段"
                      : "等待中"}
                </small>
              </div>
            </div>
          ))}
        </div>
        <div className={`confirmNode ${confirmationEvent ? "confirmed" : ""}`}>
          <ShieldCheck size={15} />
          {confirmationEvent
            ? `人工确认：${date(confirmationEvent.timestamp)}${confirmationEvent.data?.subject ? ` · ${String(confirmationEvent.data.subject)}` : ""}`
            : "等待人工确认；点击“确认执行”后才会启动。"}
        </div>
        <section className="reconstructionGate">
          <div className="sectionHeading">
            <div>
              <span>源码重构门禁</span>
              <h3>
                {reconstruction?.complete_buildable
                  ? "完整可构建"
                  : reconstructionStage(reconstruction?.stage)}
              </h3>
            </div>
            <span
              className={`pill ${reconstruction?.complete_buildable ? "done" : "partial"}`}
            >
              {reconstruction?.complete_buildable ? "全部通过" : "尚未完成"}
            </span>
          </div>
          {reconstruction ? (
            <>
              <div className="gateGrid">
                {reconstructionGates.map(([label, passed]) => (
                  <div className={passed ? "passed" : "blocked"} key={label}>
                    <ShieldCheck size={14} />
                    <span>{label}</span>
                    <b>{passed ? "通过" : "待完成"}</b>
                  </div>
                ))}
              </div>
              {Boolean(reconstruction.blocking_reasons?.length) && (
                <p>
                  阻塞项：
                  {reconstruction.blocking_reasons
                    .map(reconstructionReason)
                    .join("、")}
                </p>
              )}
            </>
          ) : (
            <p>旧任务尚未迁移重构门禁状态，不能判定为完整可构建。</p>
          )}
        </section>
        <section className="modelStage">
          <div className="sectionHeading">
            <div>
              <span>大模型重构阶段</span>
              <h3>
                {modelState
                  ? modelStatus(String(modelState.status || ""))
                  : "尚未执行"}
              </h3>
            </div>
            <span
              className={`pill ${tone(String(modelState?.status || "queued"))}`}
            >
              {modelState
                ? modelStatus(String(modelState.status || ""))
                : "等待任务"}
            </span>
          </div>
          {modelState ? (
            <>
              <div className="modelMetrics">
                <div>
                  <span>模型服务</span>
                  <b>{String(modelState.provider || "--")}</b>
                </div>
                <div>
                  <span>模型</span>
                  <b>{String(modelState.model || "--")}</b>
                </div>
                <div>
                  <span>模块调用</span>
                  <b>{Number(modelState.call_count || 0)}</b>
                </div>
                <div>
                  <span>源码修改</span>
                  <b>{Number(modelState.applied_change_count || 0)}</b>
                </div>
                <div>
                  <span>输入用量</span>
                  <b>{Number(modelState.input_tokens || 0)}</b>
                </div>
                <div>
                  <span>输出用量</span>
                  <b>{Number(modelState.output_tokens || 0)}</b>
                </div>
              </div>
              {Boolean(modelState.error) && <p>{String(modelState.error)}</p>}
              {Boolean(modelState.artifact) && (
                <code>{String(modelState.artifact)}</code>
              )}
            </>
          ) : (
            <p>
              任务完成后将显示逐模块模型调用、源码修改、模型用量与失败原因。
            </p>
          )}
        </section>
        <section className="flowEvidence">
          <FlowResultSection
            title="构建详情"
            state={buildState}
            empty="尚无隔离构建结果"
            onOpen={setPreviewPath}
          />
          <RepairLoopSection
            title="编译修复循环"
            state={buildRepair}
            onOpen={setPreviewPath}
          />
          <FlowResultSection
            title="行为对比"
            state={behaviorState}
            empty="尚无真实行为对比结果"
            onOpen={setPreviewPath}
          />
          <RepairLoopSection
            title="行为修复循环"
            state={behaviorRepair}
            onOpen={setPreviewPath}
          />
        </section>
        {retryNeeded && (
          <div className="retryNotice">
            <AlertTriangle size={16} />
            <div>
              <b>闭环尚未通过</b>
              <span>
                依赖门禁、失败或迭代耗尽后，只能从头重试整个任务流程。
              </span>
            </div>
            <button
              className="ghostBtn"
              disabled={!canWrite || !!busy}
              onClick={() => void action("retry")}
            >
              <RotateCcw size={14} />
              重试整个流程
            </button>
          </div>
        )}
        {actionMessage && <div className="inlineMsg">{actionMessage}</div>}
        <div className="actionRow">
          <button
            className="primaryBtn"
            disabled={
              !canWrite ||
              !!busy ||
              !["queued", "planned"].includes(experiment.status)
            }
            onClick={() => void action("execute")}
          >
            <Play size={15} />
            确认执行
          </button>
          <button
            className="ghostBtn"
            disabled={
              !canWrite ||
              !!busy ||
              !["queued", "planned", "running"].includes(experiment.status)
            }
            onClick={() => void action("cancel")}
          >
            <Square size={14} />
            取消
          </button>
          <button
            className="ghostBtn"
            disabled={
              !canWrite ||
              !!busy ||
              !["failed", "cancelled"].includes(experiment.status)
            }
            onClick={() => void action("retry")}
          >
            <RotateCcw size={15} />
            重试
          </button>
        </div>
        <section className="drawerSection">
          <div className="resultStats">
            <article>
              <span>产物文件</span>
              <b>{artifactFiles}</b>
            </article>
            <article>
              <span>产物总量</span>
              <b>{artifactBytes ? formatBytes(artifactBytes) : "待统计"}</b>
            </article>
            <article>
              <span>精确包树</span>
              <b>{packageBytes ? formatBytes(packageBytes) : "--"}</b>
            </article>
            <article>
              <span>执行日志</span>
              <b>
                {formatBytes(
                  Number(
                    summaryEvents[summaryEvents.length - 1]?.data?.log_bytes ||
                      summaryEvents[summaryEvents.length - 1]?.data
                        ?.output_bytes ||
                      0,
                  ),
                )}
              </b>
            </article>
          </div>
          <div className="sectionHeading">
            <h3>执行记录</h3>
            <div className="logTabs">
              <button
                className={logMode === "events" ? "active" : ""}
                onClick={() => setLogMode("events")}
              >
                关键事件 <b>{keyEvents.length}</b>
              </button>
              <button
                className={logMode === "raw" ? "active" : ""}
                onClick={() => setLogMode("raw")}
              >
                日志摘要 <b>{outputLineCount}</b>
              </button>
            </div>
          </div>
          {logMode === "events" ? (
            <div className="eventLog compact">
              {keyEvents.map((x, index) => (
                <div key={x.sequence}>
                  <span title={`原始事件序号 ${x.sequence}`}>{index + 1}</span>
                  <b>{eventLabel(x.type)}</b>
                  <p>{x.message}</p>
                  <time>{timeOnly(x.timestamp)}</time>
                </div>
              ))}
              {!keyEvents.length && <Empty text="暂无关键事件" />}
            </div>
          ) : (
            <div className="terminalOutput">
              <header>
                <span />
                <span />
                <span />
                <b>执行日志摘要</b>
              </header>
              <pre>{outputSummary}</pre>
            </div>
          )}
        </section>
        {hasSourceProject && (
          <section className="drawerSection">
            <div className="sourceProjectCallout">
              <Code2 size={21} />
              <div>
                <h3>可编辑重构源码</h3>
                <p>已生成完整构建工程，可浏览源码、修改、下载并重新构建。</p>
              </div>
              <button
                className="primaryBtn"
                onClick={() => setSourceOpen(true)}
              >
                <Code2 size={15} />
                打开源码工作区
              </button>
            </div>
          </section>
        )}
        <section className="drawerSection">
          <div className="sourceProjectCallout">
            <Wrench size={21} />
            <div>
              <h3>授权定点修改</h3>
              <p>
                按偏移定位证据，预览字节差异，验证后生成独立修改副本并支持一键回滚。
              </p>
            </div>
            <button className="primaryBtn" onClick={() => setPatchOpen(true)}>
              <Wrench size={15} />
              打开修改工作台
            </button>
          </div>
        </section>
        <section className="drawerSection">
          <h3>
            产物与报告{" "}
            <span className="sectionCount">
              {experiment.artifacts?.length || 0}
            </span>
          </h3>
          <div className="artifactList">
            {(experiment.artifacts || []).map((x, i) => {
              const path = String(x.path || x.name || `产物 ${i + 1}`);
              return (
                <ArtifactLink
                  key={path}
                  path={path}
                  size={Number(x.size || 0)}
                  onOpen={setPreviewPath}
                />
              );
            })}
            {!experiment.artifacts?.length && (
              <Empty text="任务完成后将在这里展示报告和证据产物" />
            )}
          </div>
        </section>
      </aside>
      {previewPath && (
        <ArtifactPreview
          path={previewPath}
          onClose={() => setPreviewPath("")}
        />
      )}{" "}
      {sourceOpen && (
        <SourceWorkspace
          experiment={experiment}
          identity={identity}
          onClose={() => setSourceOpen(false)}
          onChanged={onChanged}
        />
      )}{" "}
      {patchOpen && (
        <PatchWorkspace
          experiment={experiment}
          identity={identity}
          onClose={() => setPatchOpen(false)}
        />
      )}
    </>
  );
}

function FlowResultSection({
  title,
  state,
  empty,
  onOpen,
}: {
  title: string;
  state: Record<string, unknown> | null;
  empty: string;
  onOpen: (path: string) => void;
}) {
  if (!state)
    return (
      <article className="flowResult emptyResult">
        <div className="sectionHeading">
          <h3>{title}</h3>
          <span className="pill queued">等待</span>
        </div>
        <p>{empty}</p>
      </article>
    );
  const path = typeof state.artifact === "string" ? state.artifact : "";
  const metrics =
    title === "构建详情"
      ? [
          ["隔离执行", state.isolated ? "是" : "否"],
          ["阶段", Number(state.stage_count || 0)],
          ["产物", Number(state.artifact_count || 0)],
          ["耗时", `${Number(state.duration_ms || 0)} ms`],
        ]
      : [
          ["行为一致", state.behavior_equivalent ? "是" : "否"],
          ["严格验证", state.strictly_verified ? "通过" : "未通过"],
          ["比较项", Number(state.comparison_count || 0)],
          ["不一致", Number(state.mismatch_count || 0)],
        ];
  return (
    <article className="flowResult">
      <div className="sectionHeading">
        <h3>{title}</h3>
        <span className={`pill ${tone(String(state.status || ""))}`}>
          {status(String(state.status || ""))}
        </span>
      </div>
      <div className="compactMetrics">
        {metrics.map(([label, value]) => (
          <div key={String(label)}>
            <span>{label}</span>
            <b>{String(value)}</b>
          </div>
        ))}
      </div>
      {Boolean(state.error) && <p>{String(state.error)}</p>}
      {path && <ArtifactLink path={path} onOpen={onOpen} />}
    </article>
  );
}

function RepairLoopSection({
  title,
  state,
  onOpen,
}: {
  title: string;
  state: Record<string, unknown> | null;
  onOpen: (path: string) => void;
}) {
  if (!state)
    return (
      <article className="flowResult emptyResult">
        <div className="sectionHeading">
          <h3>{title}</h3>
          <span className="pill queued">等待</span>
        </div>
        <p>仅在真实失败需要模型修复时生成。</p>
      </article>
    );
  const rounds = Array.isArray(state.iterations)
    ? (state.iterations as Array<Record<string, unknown>>)
    : [];
  const usage = (
    state.usage && typeof state.usage === "object" ? state.usage : {}
  ) as Record<string, unknown>;
  const reasons = Array.isArray(state.blocking_reasons)
    ? state.blocking_reasons.map(String)
    : [];
  return (
    <article className="flowResult repairLoop">
      <div className="sectionHeading">
        <div>
          <h3>{title}</h3>
          <small>
            {Number(state.iterations_completed || 0)} 轮 ·{" "}
            模型用量 {Number(usage.total_tokens || 0)} · 已提交{" "}
            {Number(state.committed_applied_change_count || 0)} 处
          </small>
        </div>
        <span className={`pill ${tone(String(state.status || ""))}`}>
          {status(String(state.status || ""))}
        </span>
      </div>
      {reasons.length > 0 && (
        <p>阻塞：{reasons.map(repairReason).join("、")}</p>
      )}
      <div className="repairTimeline">
        {rounds.map((round, index) => {
          const evidence = (
            round.evidence_refresh && typeof round.evidence_refresh === "object"
              ? round.evidence_refresh
              : {}
          ) as Record<string, unknown>;
          const evidenceArtifacts = Array.isArray(evidence.artifacts)
            ? evidence.artifacts.map(String)
            : [];
          return (
            <details key={String(round.iteration || index)}>
              <summary>
                <span>{Number(round.iteration || index + 1)}</span>
                <b>第 {Number(round.iteration || index + 1)} 轮</b>
                <em className={`pill ${tone(String(round.status || ""))}`}>
                  {status(String(round.status || ""))}
                </em>
                <small>
                  诊断 {formatBytes(Number(round.diagnostic_bytes || 0))} · 修改{" "}
                  {Number(
                    round.model_change_count ||
                      round.attempted_applied_change_count ||
                      0,
                  )}{" "}
                  · 模型用量{" "}
                  {Number(
                    ((round.usage || {}) as Record<string, unknown>)
                      .total_tokens || 0,
                  )}
                </small>
              </summary>
              <div className="roundDetails">
                <div className="roundStateLine">
                  <span>
                    构建：
                    {round.build_before_status
                      ? status(String(round.build_before_status))
                      : "--"}{" "}
                    →{" "}
                    {round.build_after_status || round.build_result_status
                      ? status(
                          String(
                            round.build_after_status ||
                              round.build_result_status,
                          ),
                        )
                      : "--"}
                  </span>
                  <span>
                    行为不一致：
                    {Number(round.behavior_before_mismatch_count || 0)} →{" "}
                    {Number(round.behavior_after_mismatch_count || 0)}
                  </span>
                </div>
                {Boolean(round.error) && <p>{String(round.error)}</p>}
                <div className="roundArtifacts">
                  {Object.entries(round)
                    .filter(
                      ([key, value]) =>
                        [
                          "diagnostics",
                          "repair",
                          "model_repair",
                          "build_before",
                          "build_after",
                          "build_result",
                          "behavior_diff",
                          "behavior_before",
                          "behavior_after",
                        ].includes(key) && typeof value === "string",
                    )
                    .map(([key, value]) => (
                      <ArtifactLink
                        key={key}
                        path={String(value)}
                        label={artifactLabel(key)}
                        onOpen={onOpen}
                      />
                    ))}
                  {evidenceArtifacts.map((path, i) => (
                    <ArtifactLink
                      key={`evidence-${i}`}
                      path={path}
                      label="证据刷新"
                      onOpen={onOpen}
                    />
                  ))}
                </div>
              </div>
            </details>
          );
        })}
      </div>
      {typeof state.artifact === "string" && (
        <ArtifactLink
          path={state.artifact}
          label="打开循环报告"
          onOpen={onOpen}
        />
      )}
    </article>
  );
}

function ArtifactLink({
  path,
  size = 0,
  label = "打开",
  onOpen,
}: {
  path: string;
  size?: number;
  label?: string;
  onOpen: (path: string) => void;
}) {
  const json = path.toLowerCase().endsWith(".json");
  return (
    <div className="artifactItem">
      <FileJson size={15} />
      <div>
        <b title={path}>{path}</b>
        <small>
          {size ? formatBytes(size) : json ? "结构化数据证据产物" : "证据产物"}
        </small>
      </div>
      {json ? (
        <button onClick={() => onOpen(path)}>{label}</button>
      ) : (
        <ArtifactDownloadButton path={path} />
      )}
    </div>
  );
}

function ArtifactPreview({
  path,
  onClose,
}: {
  path: string;
  onClose: () => void;
}) {
  const [payload, setPayload] = useState<unknown>(null);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"summary" | "raw">("summary");
  const closeButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const controller = new AbortController();
    setPayload(null);
    setError("");
    fetch(`/api/artifacts?preview=1&path=${encodeURIComponent(path)}`, {
      headers: headers(),
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok)
          throw new Error(body.error || `预览失败：${response.status}`);
        setPayload(body.preview);
      })
      .catch((reason) => {
        if (!controller.signal.aborted)
          setError(reason instanceof Error ? reason.message : String(reason));
      });
    return () => controller.abort();
  }, [path]);
  useEffect(() => {
    closeButton.current?.focus();
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);
  const raw = payload === null ? "" : JSON.stringify(payload, null, 2);
  const summary =
    payload && typeof payload === "object" && !Array.isArray(payload)
      ? Object.entries(payload as Record<string, unknown>).slice(0, 24)
      : [];
  return (
    <div className="modalLayer artifactPreviewLayer">
      <button className="scrim" onClick={onClose} aria-label="关闭报告查看器" />
      <section className="artifactPreview" role="dialog" aria-modal="true" aria-labelledby="artifact-preview-title">
        <header>
          <div>
            <p>报告查看器</p>
            <h2 id="artifact-preview-title">{path.split("/").pop()}</h2>
            <code>{path}</code>
          </div>
          <button ref={closeButton} className="iconBtn" onClick={onClose} title="关闭" aria-label="关闭报告查看器">
            <X size={17} />
          </button>
        </header>
        <div className="logTabs">
          <button
            className={mode === "summary" ? "active" : ""}
            onClick={() => setMode("summary")}
          >
            摘要
          </button>
          <button
            className={mode === "raw" ? "active" : ""}
            onClick={() => setMode("raw")}
          >
            原始结构化数据
          </button>
        </div>
        {error ? (
          <div className="previewError">
            <AlertTriangle size={17} />
            {error}
          </div>
        ) : payload === null ? (
          <div className="sourceLoading">
            <Loader2 className="spin" />
            正在读取受限预览
          </div>
        ) : mode === "raw" ? (
          <pre>{raw}</pre>
        ) : (
          <dl className="jsonSummary">
            {summary.map(([key, value]) => (
              <div key={key}>
                <dt>{jsonKeyLabel(key)}</dt>
                <dd>{summarizeJSON(value)}</dd>
              </div>
            ))}
          </dl>
        )}
        <footer>
          <ArtifactDownloadButton path={path} label="下载原文件" className="ghostBtn" />
          <button className="primaryBtn" onClick={onClose}>
            关闭
          </button>
        </footer>
      </section>
    </div>
  );
}

function ArtifactDownloadButton({path,label="下载",className=""}:{path:string;label?:string;className?:string}) {
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const controller=useRef<AbortController|null>(null);
  const objectURL=useRef("");
  useEffect(()=>()=>{controller.current?.abort();if(objectURL.current)URL.revokeObjectURL(objectURL.current)},[]);
  const download=async()=>{
    controller.current?.abort();
    controller.current=new AbortController();
    setBusy(true);setError("");
    try{
      const response=await fetch(`/api/artifacts?path=${encodeURIComponent(path)}`,{headers:headers(),signal:controller.current.signal});
      if(!response.ok){let message=`下载失败：${response.status}`;try{const body=await response.json();if(body.error)message=body.error}catch{}throw new Error(message)}
      const blob=await response.blob();
      if(objectURL.current)URL.revokeObjectURL(objectURL.current);
      objectURL.current=URL.createObjectURL(blob);
      const anchor=document.createElement("a");anchor.href=objectURL.current;anchor.download=path.split("/").pop()||"artifact";document.body.appendChild(anchor);anchor.click();anchor.remove();
      URL.revokeObjectURL(objectURL.current);objectURL.current="";
    }catch(reason){if(!controller.current?.signal.aborted)setError(reason instanceof Error?reason.message:String(reason))}finally{setBusy(false)}
  };
  return <span className="artifactDownload"><button className={className} disabled={busy} onClick={()=>void download()}>{busy?<Loader2 className="spin" size={14}/>:<Download size={14}/>} {busy?"下载中":label}</button>{error&&<small role="alert">{error}</small>}</span>;
}

function artifactLabel(key: string) {
  return (
    (
      {
        diagnostics: "诊断",
        repair: "模型修复",
        model_repair: "模型修复",
        build_before: "构建前",
        build_after: "构建后",
        build_result: "构建结果",
        behavior_diff: "行为差异",
        behavior_before: "修复前行为",
        behavior_after: "修复后行为",
        evidence_refresh: "证据刷新",
      } as Record<string, string>
    )[key] || key
  );
}
function repairReason(value: string) {
  return (
    (
      {
        repair_iteration_budget_exhausted: "修复轮次已耗尽",
        diagnostic_byte_budget_exhausted: "诊断容量已耗尽",
        behavior_repair_iteration_budget_exhausted: "行为修复轮次已耗尽",
        behavior_repair_token_budget_exhausted: "模型用量预算已耗尽",
        behavior_validation_spec_required: "缺少行为验证规范",
        usable_build_diagnostics_required: "缺少可用编译诊断",
      } as Record<string, string>
    )[value] || value
  );
}
function jsonKeyLabel(value: string) {
  return (
    (
      {
        status: "状态",
        passed: "是否通过",
        blocking_reasons: "阻塞原因",
        iterations: "迭代记录",
        usage: "模型用量",
        artifacts: "产物",
        summary: "摘要",
        diagnostics: "诊断",
        comparisons: "比较项",
      } as Record<string, string>
    )[value] || value
  );
}
function summarizeJSON(value: unknown) {
  if (value === null || value === undefined) return "--";
  if (typeof value === "string")
    return value.length > 180 ? `${value.slice(0, 180)}…` : value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (Array.isArray(value)) return `${value.length} 项`;
  return `${Object.keys(value as object).length} 个字段`;
}

type PatchRecord = {
  id: string;
  status: string;
  target: string;
  offset: number;
  length: number;
  expected_hex: string;
  replacement_hex: string;
  source_sha256: string;
  patched_sha256?: string;
  output: string;
  error?: string;
  updated_at: string;
};
type AIPatchPlan = {
  id: string;
  status: string;
  mode: string;
  summary: string;
  evidence: string[];
  source_changes: Array<{
    path: string;
    before: string;
    after: string;
    reason: string;
  }>;
  validation: string[];
  risks: string[];
  provider: string;
  model: string;
};

function PatchWorkspace(props: {
  experiment: Experiment;
  identity: Identity;
  onClose: () => void;
}) {
  const { experiment, identity, onClose } = props;
  const canWrite = ["admin", "analyst"].includes(identity?.role || "");
  const [mode, setMode] = useState<"instruction" | "hex">("instruction");
  const [instruction, setInstruction] = useState("");
  const [target, setTarget] = useState("");
  const [plan, setPlan] = useState<AIPatchPlan | null>(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const call = async (action: string, body: Record<string, unknown>) => {
    setBusy(action);
    try {
      const response = await fetch(
        `/api/experiments/${experiment.id}/patches/${action}`,
        {
          method: "POST",
          headers: headers({ "Content-Type": "application/json" }),
          body: JSON.stringify(body),
        },
      );
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || `请求失败：${response.status}`);
      return payload;
    } finally {
      setBusy("");
    }
  };
  const createPlan = async () => {
    if (!canWrite) return setMessage("只读角色不能生成修改方案。");
    try {
      const payload = await call("ai-plan", {
        instruction,
        target,
        mode: "source_edit",
      });
      setPlan(payload.plan);
      setMessage("方案已生成。请逐项审查差异，确认后再应用。");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  };
  const apply = async () => {
    if (!plan || !confirm(`确认修改 ${plan.source_changes.length} 个源码文件？应用前会自动备份。`)) return;
    try {
      const payload = await call("ai-apply", {
        planID: plan.id,
        confirmation: "APPLY_AI_SOURCE_CHANGES",
      });
      setPlan(payload.plan);
      setMessage("源码修改已应用。下一步请执行真实构建验证。");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  };
  const rollback = async () => {
    if (!plan || !confirm("确认恢复本方案应用前的全部源码？")) return;
    try {
      const payload = await call("ai-rollback", {
        planID: plan.id,
        confirmation: "ROLLBACK_AI_SOURCE_CHANGES",
      });
      setPlan(payload.plan);
      setMessage("已恢复修改前的源码。");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  };
  const build = async () => {
    setBusy("build");
    try {
      const response = await fetch(`/api/experiments/${experiment.id}/build`, {
        method: "POST",
        headers: headers({ "Content-Type": "application/json" }),
        body: JSON.stringify({ confirmation: "BUILD_RECONSTRUCTED_SOURCE" }),
      });
      const payload = await response.json();
      setMessage(response.ok ? `真实构建已完成。\n${payload.output || ""}` : `构建失败：\n${payload.error || payload.output || "未知错误"}`);
    } finally {
      setBusy("");
    }
  };
  const download = async () => {
    setBusy("download");
    try {
      const response = await fetch(`/api/experiments/${experiment.id}/source/archive`, { headers: headers() });
      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.error || "源码工程尚未生成");
      }
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `完整源码工程-${experiment.id.slice(0, 8)}.zip`;
      anchor.click();
      URL.revokeObjectURL(url);
      setMessage("完整源码工程 ZIP 已导出，目录结构和构建文件均已保留。");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy("");
    }
  };
  if (mode === "hex") {
    return <HexPatchWorkspace {...props} onBack={() => setMode("instruction")} />;
  }
  return (
    <div className="sourceWorkspaceLayer">
      <section className="patchWorkspace instructionWorkspace">
        <header>
          <div>
            <p>大模型源码修改工作台</p>
            <h2>{experiment.name}</h2>
            <code>用中文描述目标，模型基于实际重构源码生成可审查差异</code>
          </div>
          <div className="sourceActions">
            <button className="ghostBtn" disabled={!!busy} onClick={() => void download()}>
              <Download size={15} />导出完整源码工程
            </button>
            <button className="ghostBtn" onClick={() => setMode("hex")}>
              <Terminal size={15} />高级十六进制
            </button>
            <button className="iconBtn" onClick={onClose} title="关闭修改工作台"><X size={17} /></button>
          </div>
        </header>
        <div className="instructionGrid">
          <aside className="instructionComposer">
            <div className="stepLabel"><span>1</span>描述修改目标</div>
            <textarea
              rows={9}
              value={instruction}
              onChange={(event) => setInstruction(event.target.value)}
              placeholder="例如：将设置页的默认重试次数改为 5，保留原有错误提示，并补充边界检查。"
              disabled={!canWrite || !!busy}
            />
            <label>优先定位的源码文件（可选）
              <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="例如 src/config.cpp" />
            </label>
            <button className="primaryBtn planCommand" disabled={!canWrite || !!busy || instruction.trim().length < 4} onClick={() => void createPlan()}>
              {busy === "ai-plan" ? <Loader2 className="spin" size={16} /> : <Zap size={16} />}
              让大模型生成修改方案
            </button>
            <div className="workflowRail">
              <span className={plan ? "done" : "active"}>理解指令</span>
              <span className={plan ? "done" : ""}>定位源码</span>
              <span className={plan?.status === "applied" ? "done" : ""}>确认应用</span>
              <span>真实构建</span>
            </div>
            {!canWrite && <div className="editorMessage">只读角色可以查看和导出源码，但不能生成或应用修改。</div>}
          </aside>
          <main className="aiPlanReview">
            {!plan ? (
              <div className="planEmpty"><Code2 size={30} /><b>等待修改指令</b><span>模型只会修改实际存在的源码文件；证据不足时会停止并说明缺少内容。</span></div>
            ) : (
              <>
                <section className="planHeading">
                  <div><span>模型理解</span><h3>{plan.summary}</h3></div>
                  <div className="modelStamp"><b>{plan.model}</b><small>{plan.provider}</small></div>
                </section>
                <section className="planFacts">
                  <article><span>涉及文件</span><b>{plan.source_changes.length}</b></article>
                  <article><span>方案状态</span><b>{status(plan.status)}</b></article>
                  <article><span>执行方式</span><b>源码修改</b></article>
                </section>
                <div className="sourceDiffList">
                  {plan.source_changes.map((change) => (
                    <details open key={change.path}>
                      <summary><Code2 size={14} /><code>{change.path}</code><span>{change.reason}</span></summary>
                      <div className="sourceDiffColumns">
                        <article><b>修改前</b><pre>{change.before}</pre></article>
                        <article><b>修改后</b><pre>{change.after}</pre></article>
                      </div>
                    </details>
                  ))}
                </div>
                {(plan.evidence.length > 0 || plan.risks.length > 0) && <section className="reviewNotes">
                  <div><b>定位依据</b>{plan.evidence.map((item) => <span key={item}>{item}</span>)}</div>
                  <div><b>风险提示</b>{plan.risks.map((item) => <span key={item}>{item}</span>)}</div>
                </section>}
              </>
            )}
          </main>
          <aside className="executionPanel">
            <div className="stepLabel"><span>2</span>确认与验证</div>
            <button className="primaryBtn" disabled={!canWrite || !!busy || plan?.status !== "planned"} onClick={() => void apply()}><Wrench size={15} />确认应用源码修改</button>
            <button className="primaryBtn" disabled={!canWrite || !!busy || plan?.status !== "applied"} onClick={() => void build()}>{busy === "build" ? <Loader2 className="spin" size={15} /> : <Hammer size={15} />}真实构建验证</button>
            <button className="ghostBtn" disabled={!canWrite || !!busy || plan?.status !== "applied"} onClick={() => void rollback()}><RotateCcw size={15} />一键回滚源码</button>
            <button className="ghostBtn" disabled={!!busy} onClick={() => void download()}><Download size={15} />导出当前完整工程</button>
            {plan?.validation?.length ? <section className="validationList"><b>建议验证</b>{plan.validation.map((item) => <span key={item}><ShieldCheck size={12} />{item}</span>)}</section> : null}
            {message && <pre className="commandMessage">{message}</pre>}
          </aside>
        </div>
      </section>
    </div>
  );
}

function HexPatchWorkspace({
  experiment,
  identity,
  onClose,
  onBack,
}: {
  experiment: Experiment;
  identity: Identity;
  onClose: () => void;
  onBack: () => void;
}) {
  const canWrite = ["admin", "analyst"].includes(identity?.role || "");
  const [target, setTarget] = useState(experiment.sample);
  const [offset, setOffset] = useState("0x0");
  const [length, setLength] = useState(256);
  const [expected, setExpected] = useState("");
  const [replacement, setReplacement] = useState("");
  const [context, setContext] = useState("");
  const [contextStart, setContextStart] = useState(0);
  const [markStart, setMarkStart] = useState<number | null>(null);
  const [markEnd, setMarkEnd] = useState<number | null>(null);
  const [hash, setHash] = useState("");
  const [fileSize, setFileSize] = useState(0);
  const [records, setRecords] = useState<PatchRecord[]>([]);
  const [selected, setSelected] = useState<PatchRecord | null>(null);
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const request = async (action: string, body: Record<string, unknown>) => {
    if (!canWrite && action !== "inspect")
      throw new Error("只读角色不能修改程序。");
    setBusy(action);
    const r = await fetch(
      `/api/experiments/${experiment.id}/patches/${action}`,
      {
        method: "POST",
        headers: headers({ "Content-Type": "application/json" }),
        body: JSON.stringify(body),
      },
    );
    const p = await r.json();
    setBusy("");
    if (!r.ok) throw new Error(p.error || `请求失败：${r.status}`);
    return p;
  };
  const load = async () => {
    const r = await fetch(`/api/experiments/${experiment.id}/patches`, {
      headers: headers(),
      cache: "no-store",
    });
    const p = await r.json();
    if (r.ok) {
      setRecords(p.patches || []);
      if (!selected && (p.patches || []).length) setSelected(p.patches[0]);
    }
  };
  useEffect(() => {
    void load();
    void inspect(experiment.sample, "0x0");
  }, []);
  const inspect = async (targetValue = target, offsetValue = offset) => {
    try {
      const p = await request("inspect", {
        target: targetValue,
        offset: offsetValue,
        length,
      });
      setContext(p.context_hex);
      setContextStart(Number(p.context_start || 0));
      setHash(p.target_sha256);
      setFileSize(Number(p.target_size || 0));
      setMarkStart(null);
      setMarkEnd(null);
      setExpected("");
      setReplacement("");
      setMessage(`已打开 ${p.target_size} 字节，当前查看 ${p.offset_hex}`);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    }
  };
  const upload = async (file: File) => {
    if (!canWrite) {
      setMessage("只读角色不能上传程序。");
      return;
    }
    setBusy("upload");
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      const r = await fetch("/api/uploads", {
        method: "POST",
        headers: headers(),
        body: form,
      });
      const p = await r.json();
      if (!r.ok) throw new Error(p.error || "打开程序失败");
      setTarget(p.path);
      setOffset("0x0");
      setMessage(`已打开 ${file.name}`);
      await inspect(p.path, "0x0");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy("");
    }
  };
  const bytes = context.match(/.{2}/g) || [];
  const markByte = (absolute: number, extend: boolean) => {
    let start = absolute,
      end = absolute;
    if (extend && markStart !== null) {
      start = Math.min(markStart, absolute);
      end = Math.max(markStart, absolute);
    }
    setMarkStart(start);
    setMarkEnd(end);
    const localStart = start - contextStart;
    const selectedHex = bytes
      .slice(localStart, localStart + end - start + 1)
      .join("");
    setOffset(`0x${start.toString(16).toUpperCase()}`);
    setExpected(selectedHex);
    setReplacement(selectedHex);
    setMessage(
      `已标记 0x${start.toString(16).toUpperCase()} - 0x${end.toString(16).toUpperCase()}，共 ${end - start + 1} 字节`,
    );
  };
  const plan = async () => {
    if (!canWrite) {
      setMessage("只读角色不能创建修改计划。");
      return;
    }
    try {
      const p = await request("plan", {
        target,
        offset,
        expected_hex: expected,
        replacement_hex: replacement,
      });
      setSelected(p.patch);
      setMessage("计划验证通过，尚未写入文件");
      await load();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    }
  };
  const mutate = async (action: "apply" | "verify" | "rollback") => {
    if (!canWrite) {
      setMessage("只读角色不能执行修改操作。");
      return;
    }
    if (!selected) return;
    try {
      const confirmation =
        action === "apply"
          ? "APPLY_AUTHORIZED_PATCH"
          : action === "rollback"
            ? "ROLLBACK_AUTHORIZED_PATCH"
            : undefined;
      if (
        confirmation &&
        !confirm(
          action === "apply"
            ? "确认生成定点修改后的独立副本？"
            : "确认生成并验证回滚副本？",
        )
      )
        return;
      const p = await request(action, { patch_id: selected.id, confirmation });
      setMessage(
        action === "verify"
          ? p.matches
            ? "哈希验证通过"
            : "哈希验证失败"
          : action === "apply"
            ? "修改副本已生成并写入审计记录"
            : "回滚副本已生成且恢复哈希验证通过",
      );
      if (p.patch) setSelected(p.patch);
      await load();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    }
  };
  const group = (value: string) =>
    value
      .replace(/\s/g, "")
      .match(/.{1,2}/g)
      ?.join(" ") || "";
  return (
    <div className="sourceWorkspaceLayer">
      <section className="patchWorkspace">
        <header>
          <div>
            <p>授权定点修改工作台</p>
            <h2>{experiment.name}</h2>
            <code>{target}</code>
          </div>
          <div className="sourceActions">
            <button className="ghostBtn" onClick={onBack}><ChevronRight size={15} />返回指令模式</button>
            <label className="openBinaryBtn">
              <HardDriveUpload size={15} />
              {busy === "upload" ? "正在打开" : "打开本地程序"}
              <input
                type="file"
                disabled={!canWrite || !!busy}
                onChange={(e) =>
                  e.target.files?.[0] && void upload(e.target.files[0])
                }
              />
            </label>
            <button
              className="iconBtn"
              onClick={onClose}
              title="关闭修改工作台"
            >
              <X size={17} />
            </button>
          </div>
        </header>
        <div className="patchGrid">
          <aside className="patchTarget">
            <h3>文件与定位</h3>
            <label>
              工作区文件
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </label>
            <label>
              跳转到文件偏移
              <input
                value={offset}
                onChange={(e) => setOffset(e.target.value)}
                placeholder="0x4010"
              />
            </label>
            <label>
              每页读取字节
              <input
                type="number"
                min={16}
                max={4096}
                value={length}
                onChange={(e) => setLength(Number(e.target.value))}
              />
            </label>
            <button
              className="primaryBtn"
              disabled={!!busy}
              onClick={() => void inspect()}
            >
              {busy === "inspect" ? (
                <Loader2 className="spin" size={15} />
              ) : (
                <Search size={15} />
              )}
              跳转并读取
            </button>
            <div className="hashBlock">
              <span>文件大小</span>
              <code>{fileSize ? formatBytes(fileSize) : "--"}</code>
              <span>原始 SHA-256</span>
              <code>{hash || "正在读取"}</code>
            </div>
            <h3>修改历史</h3>
            <div className="patchHistory">
              {records.map((x) => (
                <button
                  className={selected?.id === x.id ? "active" : ""}
                  onClick={() => setSelected(x)}
                  key={x.id}
                >
                  <b>0x{x.offset.toString(16).toUpperCase()}</b>
                  <span className={`pill ${tone(x.status)}`}>
                    {status(x.status)}
                  </span>
                  <small>{date(x.updated_at)}</small>
                </button>
              ))}
              {!records.length && <Empty text="暂无修改记录" />}
            </div>
          </aside>
          <main className="patchEvidence">
            <div className="editorBar">
              <code>十六进制视图 / 按住换挡键并单击以扩展标记范围</code>
              <span className="saved">手动标记</span>
            </div>
            <div className="hexGrid">
              {bytes.length ? (
                Array.from(
                  { length: Math.ceil(bytes.length / 16) },
                  (_, row) => (
                    <div className="hexRow" key={row}>
                      <code>
                        {(contextStart + row * 16)
                          .toString(16)
                          .toUpperCase()
                          .padStart(8, "0")}
                      </code>
                      <div>
                        {bytes
                          .slice(row * 16, row * 16 + 16)
                          .map((byte, column) => {
                            const absolute = contextStart + row * 16 + column;
                            const marked =
                              markStart !== null &&
                              markEnd !== null &&
                              absolute >= markStart &&
                              absolute <= markEnd;
                            return (
                              <button
                                className={marked ? "marked" : ""}
                                key={absolute}
                                onClick={(e) => markByte(absolute, e.shiftKey)}
                                title={`0x${absolute.toString(16).toUpperCase()}`}
                              >
                                {byte}
                              </button>
                            );
                          })}
                      </div>
                      <span>
                        {bytes
                          .slice(row * 16, row * 16 + 16)
                          .map((x) => {
                            const n = parseInt(x, 16);
                            return n >= 32 && n < 127
                              ? String.fromCharCode(n)
                              : ".";
                          })
                          .join("")}
                      </span>
                    </div>
                  ),
                )
              ) : (
                <div className="hexEmpty">
                  {busy === "inspect"
                    ? "正在读取程序字节…"
                    : "选择本地程序或输入偏移后读取"}
                </div>
              )}
            </div>
            <section className="byteDiff">
              <article>
                <span>标记的原始字节</span>
                <code>{group(expected) || "请在上方字节网格中单击标记"}</code>
              </article>
              <article>
                <span>准备替换为</span>
                <code>{group(replacement) || "--"}</code>
              </article>
            </section>
            <div className="diffLegend">
              <span />
              单击选择一个字节，按住换挡键再单击可选择连续范围。
            </div>
          </main>
          <aside className="patchPlan">
            <h3>修改计划</h3>
            <label>
              原始字节
              <textarea
                rows={5}
                value={expected}
                onChange={(e) => setExpected(e.target.value)}
                spellCheck={false}
                disabled={!canWrite}
              />
            </label>
            <label>
              替换字节
              <textarea
                rows={5}
                value={replacement}
                onChange={(e) => setReplacement(e.target.value)}
                spellCheck={false}
                disabled={!canWrite}
              />
            </label>
            <button
              className="primaryBtn"
              disabled={
                !canWrite ||
                !!busy ||
                !expected ||
                expected.replace(/\s/g, "").length !==
                  replacement.replace(/\s/g, "").length
              }
              onClick={() => void plan()}
            >
              <ShieldCheck size={15} />
              验证修改计划
            </button>
            {selected && (
              <section className="patchSummary">
                <b>{selected.status}</b>
                <code>{selected.id}</code>
                <span>输出副本</span>
                <code>{selected.output}</code>
                {selected.patched_sha256 && (
                  <>
                    <span>修改后 SHA-256</span>
                    <code>{selected.patched_sha256}</code>
                  </>
                )}
              </section>
            )}
            <div className="patchActions">
              <button
                className="primaryBtn"
                disabled={!canWrite || !!busy || !selected || selected.status !== "planned"}
                onClick={() => void mutate("apply")}
              >
                <Wrench size={15} />
                确认执行
              </button>
              <button
                className="ghostBtn"
                disabled={!canWrite || !!busy || !selected || !selected.patched_sha256}
                onClick={() => void mutate("verify")}
              >
                <ShieldCheck size={15} />
                验证
              </button>
              <button
                className="ghostBtn"
                disabled={!canWrite || !!busy || !selected || !selected.patched_sha256}
                onClick={() => void mutate("rollback")}
              >
                <RotateCcw size={15} />
                一键回滚
              </button>
            </div>
            {!canWrite && (
              <div className="editorMessage">
                只读角色仅可查看修改证据，不能上传、规划、执行、验证或回滚修改。
              </div>
            )}
            {message && <div className="editorMessage">{message}</div>}
          </aside>
        </div>
      </section>
    </div>
  );
}

type SourceFile = {
  path: string;
  size: number;
  editable: boolean;
  directory?: boolean;
};
function SourceWorkspace({
  experiment,
  identity,
  onClose,
  onChanged,
}: {
  experiment: Experiment;
  identity: Identity;
  onClose: () => void;
  onChanged: () => Promise<void>;
}) {
  const canWrite = ["admin", "analyst"].includes(identity?.role || "");
  const [files, setFiles] = useState<SourceFile[]>([]);
  const [root, setRoot] = useState("");
  const [selected, setSelected] = useState("");
  const [content, setContent] = useState("");
  const [savedContent, setSavedContent] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [buildOutput, setBuildOutput] = useState("");
  const [fileQuery, setFileQuery] = useState("");
  const readFile = async (path: string) => {
    setBusy("file");
    try {
      const r = await fetch(
        `/api/experiments/${experiment.id}/source?path=${encodeURIComponent(path)}`,
        { headers: headers(), cache: "no-store" },
      );
      const p = await r.json();
      if (r.ok) {
        setSelected(path);
        setContent(p.content || "");
        setSavedContent(p.content || "");
        setMessage("");
      } else setMessage(p.error || "无法读取文件");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "无法读取文件");
    } finally {
      setBusy("");
    }
  };
  const loadProject = async () => {
    setBusy("load");
    setMessage("");
    try {
      const r = await fetch(`/api/experiments/${experiment.id}/source`, {
        headers: headers(),
        cache: "no-store",
      });
      const p = await r.json();
      if (!r.ok) {
        setMessage(p.error || "无法读取源码工程");
        return;
      }
      const loaded = (p.files || []) as SourceFile[];
      setRoot(p.project_root || "");
      setFiles(loaded);
      const first =
        loaded.find((file) => file.path === "src/reconstructed.c") ||
        loaded.find((file) => file.editable);
      if (first) await readFile(first.path);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "源码工程请求失败");
    } finally {
      setBusy("");
    }
  };
  const loadFile = async (path: string) => {
    const file = files.find((item) => item.path === path);
    if (file?.directory) return;
    if (
      content !== savedContent &&
      !confirm("当前文件有未保存修改，确定切换吗？")
    )
      return;
    await readFile(path);
  };
  useEffect(() => {
    void loadProject();
  }, []);
  const save = async () => {
    if (!canWrite) {
      setMessage("只读角色不能保存源码。");
      return;
    }
    const currentFile = files.find((file) => file.path === selected);
    if (!selected || !currentFile?.editable) {
      setMessage("请先在左侧选择一个可编辑的源码文件。");
      return;
    }
    if (content === savedContent) {
      setMessage("当前文件没有需要保存的修改。请先在编辑器中修改内容。");
      return;
    }
    setBusy("save");
    const r = await fetch(`/api/experiments/${experiment.id}/source/file`, {
      method: "PUT",
      headers: headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ path: selected, content }),
    });
    const p = await r.json();
    setBusy("");
    if (r.ok) {
      setSavedContent(content);
      setMessage("源码已保存");
    } else setMessage(p.error || "保存失败");
  };
  const build = async () => {
    if (!canWrite) {
      setMessage("只读角色不能发起构建。");
      return;
    }
    if (content !== savedContent) {
      setMessage("请先保存当前文件");
      return;
    }
    setBusy("build");
    setBuildOutput("正在配置并构建完整工程...");
    const r = await fetch(`/api/experiments/${experiment.id}/build`, {
      method: "POST",
      headers: headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ confirmation: "BUILD_RECONSTRUCTED_SOURCE" }),
    });
    const p = await r.json();
    setBusy("");
    setBuildOutput(p.output || p.error || "构建未返回输出");
    setMessage(r.ok ? "构建完成" : "构建失败，请查看输出");
    if (r.ok) await onChanged();
  };
  const download = async () => {
    setBusy("download");
    const r = await fetch(`/api/experiments/${experiment.id}/source/archive`, {
      headers: headers(),
    });
    if (r.ok) {
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `reconstructed-${experiment.id.slice(0, 8)}.zip`;
      anchor.click();
      URL.revokeObjectURL(url);
      setMessage("源码工程已下载");
    } else setMessage("下载失败");
    setBusy("");
  };
  const selectedFile = files.find((file) => file.path === selected);
  const dirty = content !== savedContent;
  const visibleFiles = files.filter((file) =>
    file.path.toLowerCase().includes(fileQuery.trim().toLowerCase()),
  );
  return (
    <div className="sourceWorkspaceLayer">
      <section className="sourceWorkspace">
        <header>
          <div>
            <p>组合重构工程</p>
            <h2>{experiment.name}</h2>
            <code>{root}</code>
          </div>
          <div className="sourceActions">
            <button
              className="ghostBtn"
              disabled={!!busy}
              onClick={() => void download()}
            >
              <Download size={15} />
              下载完整工程
            </button>
            <button
              className="primaryBtn"
              disabled={!canWrite || !!busy || !selectedFile?.editable}
              title={
                !selectedFile?.editable
                  ? "请先选择可编辑源码文件"
                  : dirty
                    ? "保存当前修改"
                    : "当前无修改，点击可查看提示"
              }
              onClick={() => void save()}
            >
              <Save size={15} />
              保存源码
            </button>
            <button
              className="primaryBtn"
              disabled={!canWrite || !!busy || dirty}
              onClick={() => void build()}
            >
              {busy === "build" ? (
                <Loader2 className="spin" size={15} />
              ) : (
                <Hammer size={15} />
              )}
              构建整个工程
            </button>
            <button
              className="iconBtn"
              onClick={onClose}
              title="关闭源码工作区"
            >
              <X size={17} />
            </button>
          </div>
          {!canWrite && (
            <div className="editorMessage">
              只读角色仅可查看和下载，不能保存源码或发起构建。
            </div>
          )}
        </header>
        <div className="sourceWorkspaceBody">
          <aside>
            <h3>
              工程结构 <span>{files.length}</span>
            </h3>
            <p className="sourceTreeHint">
              软件包目录保留原包结构，目标目录放置逐目标重构源码；一次构建顶层工程。
            </p>
            <div className="sourceFileSearch">
              <Search size={14} />
              <input
                value={fileQuery}
                onChange={(e) => setFileQuery(e.target.value)}
                placeholder="筛选工程文件"
              />
            </div>
            <div className="sourceTree">
              {busy === "load" ? (
                <div className="sourceLoading">
                  <Loader2 className="spin" />
                  正在读取组合工程，安卓安装包文件树可能需要数秒
                </div>
              ) : (
                visibleFiles.map((file) => (
                  <button
                    className={`${selected === file.path ? "active " : ""}${file.directory ? "directory" : ""}`}
                    key={file.path}
                    onClick={() => void loadFile(file.path)}
                  >
                    <Code2 size={13} />
                    <span>
                      {file.path}
                      {file.directory ? " /" : ""}
                    </span>
                    <small>
                      {file.directory ? "目录" : formatBytes(file.size)}
                    </small>
                  </button>
                ))
              )}
              {!busy && !visibleFiles.length && (
                <Empty text={message || "没有可显示的工程文件"} />
              )}
            </div>
          </aside>
          <main>
            <div className="editorBar">
              <code>{selected || "请选择源码文件"}</code>
              <span className={dirty ? "dirty" : "saved"}>
                {dirty ? "未保存" : selectedFile?.editable ? "可编辑" : "只读"}
              </span>
            </div>
            {busy === "file" ? (
              <div className="sourceLoading">
                <Loader2 className="spin" />
                正在读取文件
              </div>
            ) : (
              <textarea
                className="codeEditor"
                spellCheck={false}
                value={content}
                onChange={(e) => setContent(e.target.value)}
                disabled={!canWrite || !selectedFile?.editable}
              />
            )}{" "}
            {message && <div className="editorMessage">{message}</div>}
            {buildOutput && (
              <section className="buildOutput">
                <h3>整个工程的构建输出</h3>
                <pre>{buildOutput}</pre>
              </section>
            )}
          </main>
        </div>
      </section>
    </div>
  );
}

function flowProgress(
  statusValue: string,
  outputCount: number,
  reported: number,
) {
  if (statusValue === "completed") return 100;
  if (statusValue === "partial") return 82;
  if (statusValue === "failed" || statusValue === "cancelled") return 100;
  if (statusValue === "queued") return 8;
  if (statusValue === "planned") return 18;
  return Math.max(
    reported,
    Math.min(92, Math.round(28 + 64 * (1 - Math.exp(-outputCount / 36)))),
  );
}
function elapsed(created?: string) {
  if (!created) return "未知";
  const seconds = Math.max(
    0,
    Math.floor((Date.now() - new Date(created).valueOf()) / 1000),
  );
  const minutes = Math.floor(seconds / 60);
  return minutes ? `${minutes}分 ${seconds % 60}秒` : `${seconds}秒`;
}
function eventLabel(value: string) {
  return (
    (
      {
        queued: "进入队列",
        started: "开始执行",
        execution_confirmed: "人工确认",
        provider_fallback: "服务回退",
        model_completed: "模型阶段完成",
        model_failed: "模型阶段失败",
        model_dependency_gated: "模型依赖未就绪",
        build_repair_recorded: "编译修复已记录",
        behavior_repair_recorded: "行为修复已记录",
        completed: "执行完成",
        failed: "执行失败",
        cancelled: "已取消",
        recovered: "任务恢复",
        source_saved: "源码已保存",
        build_started: "开始构建",
        build_completed: "构建完成",
        build_failed: "构建失败",
      } as Record<string, string>
    )[value] || value
  );
}
function modelStatus(value: string) {
  return (
    (
      {
        executed: "逐模块调用完成",
        failed: "模型阶段失败",
        "dependency-gated": "模型依赖未就绪",
      } as Record<string, string>
    )[value] || value
  );
}
function reconstructionStage(value?: string) {
  return (
    (
      {
        analysis_pending: "等待分析",
        source_generation_pending: "等待源码生成",
        build_pending: "等待真实构建",
        behavior_validation_pending: "等待行为验证",
        complete_buildable: "完整可构建",
      } as Record<string, string>
    )[value || ""] || "尚未迁移"
  );
}
function reconstructionReason(value: string) {
  return (
    (
      {
        analysis_not_complete: "分析未完成",
        source_not_generated: "源码未生成",
        structure_not_complete: "工程结构未完整",
        dependencies_not_locked: "依赖未锁定",
        build_not_passed: "真实构建未通过",
        behavior_validation_not_passed: "行为验证未通过",
        model_reconstruction_failed: "大模型源码重构失败",
        model_provider_not_ready: "大模型服务未就绪",
      } as Record<string, string>
    )[value] || value
  );
}
function timeOnly(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf())
    ? ""
    : parsed.toLocaleTimeString("zh-CN", { hour12: false });
}
function formatBytes(value: number) {
  if (value < 1024) return `${value} 字节`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} 千字节`;
  return `${(value / 1024 / 1024).toFixed(1)} 兆字节`;
}

function Toolbar({
  query,
  setQuery,
  children,
}: {
  query: string;
  setQuery: (s: string) => void;
  children?: React.ReactNode;
}) {
  return (
    <div className="toolbar">
      <div className="search">
        <Search size={16} />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="搜索任务、样本或状态"
        />
      </div>
      {children}
    </div>
  );
}
function Panel({
  title,
  children,
  wide,
  action,
  onAction,
}: {
  title: string;
  children: React.ReactNode;
  wide?: boolean;
  action?: string;
  onAction?: () => void;
}) {
  return (
    <section className={`panel ${wide ? "wide" : ""}`}>
      <header>
        <h2>{title}</h2>
        {action && (
          <button className="textBtn" onClick={onAction}>
            {action}
            <ChevronRight size={14} />
          </button>
        )}
      </header>
      {children}
    </section>
  );
}
function Metric({
  label,
  value,
  detail,
  icon: Icon,
  tone: t,
}: {
  label: string;
  value: string | number;
  detail: string;
  icon: typeof Activity;
  tone: string;
}) {
  return (
    <article className={`metric ${t}`}>
      <Icon size={18} />
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}
function Banner({ text }: { text: string }) {
  return (
    <div className="banner">
      <AlertTriangle size={17} />
      {text}
    </div>
  );
}
function Empty({ text }: { text: string }) {
  return <div className="empty">{text}</div>;
}
function status(value: string) {
  return (
    (
      {
        queued: "已排队",
        planned: "已验证",
        running: "运行中",
        repairing: "修复中",
        mismatch: "仍有差异",
        completed: "已完成",
        passed: "通过",
        executed: "已执行",
        applied: "已执行",
        rolled_back: "已回滚",
        rollback_failed: "回滚失败",
        failed: "失败",
        timed_out: "构建超时",
        error: "构建异常",
        invalid: "证据无效",
        exhausted: "迭代已耗尽",
        cancelled: "已取消",
        verified: "已验证",
        "dependency-gated": "依赖受限",
        dependency_gated: "依赖受限",
        repository_ready: "仓库就绪",
        ready_to_run: "可运行验收",
        partial: "部分就绪",
        unavailable: "不可用",
        unsupported_host: "主机不支持",
      } as Record<string, string>
    )[value] || value
  );
}
function tone(value: string) {
  if (
    [
      "completed",
      "passed",
      "executed",
      "verified",
      "repository_ready",
      "ready_to_run",
      "applied",
      "rolled_back",
    ].includes(value)
  )
    return "done";
  if (
    [
      "running",
      "repairing",
      "mismatch",
      "planned",
      "partial",
      "dependency-gated",
      "dependency_gated",
      "unsupported_host",
      "exhausted",
    ].includes(value)
  )
    return "partial";
  if (["failed", "timed_out", "error", "invalid", "unavailable", "rollback_failed"].includes(value))
    return "missing";
  return "queued";
}
function date(value?: string) {
  if (!value) return "未知";
  const d = new Date(value);
  return Number.isNaN(d.valueOf())
    ? value
    : new Intl.DateTimeFormat("zh-CN", {
        dateStyle: "short",
        timeStyle: "short",
      }).format(d);
}
