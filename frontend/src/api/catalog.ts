export type CatalogKind = 'skill' | 'tool' | 'capability' | 'script' | 'dependency' | 'extension';

export type CatalogItem = {
  id: string;
  name: string;
  kind: CatalogKind;
  description: string;
  source: string;
  registered: boolean;
  callable: boolean;
  dependency_ready: boolean;
  accepted: boolean;
  missing_dependencies: string[];
  acceptance_command: string;
  callable_name: string;
  execution_boundary: string;
  routes: string[];
  metadata: Record<string, unknown>;
};

export type CatalogPayload = {
  generated_at?: string;
  items: CatalogItem[];
};

const KINDS: CatalogKind[] = ['skill', 'tool', 'capability', 'script', 'dependency', 'extension'];

function bool(value: unknown, fallback = false) {
  return typeof value === 'boolean' ? value : fallback;
}

function available(value: unknown, fallback = false) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.trim().length > 0 && !['false', 'unavailable', 'missing'].includes(value.toLowerCase());
  return fallback;
}

function text(value: unknown) {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeItem(raw: unknown, fallbackKind: CatalogKind, index: number): CatalogItem {
  const item = raw && typeof raw === 'object' ? raw as Record<string, unknown> : {};
  const status = item.status && typeof item.status === 'object'
    ? item.status as Record<string, unknown>
    : {};
  const rawKind = text(item.kind || item.type).toLowerCase() as CatalogKind;
  const kind = KINDS.includes(rawKind) ? rawKind : fallbackKind;
  const missing = item.missing_dependencies ?? item.missing ?? status.missing_dependencies;
  return {
    id: text(item.id || item.name || kind + '-' + index),
    name: text(item.name || item.id || '未命名目录项'),
    kind,
    description: text(item.description || item.detail || item.summary),
    source: text(item.source || item.module || item.path || item.provider),
    registered: bool(item.registered ?? status.registered, true),
    callable: available(item.callable ?? item.available ?? status.callable),
    dependency_ready: bool(item.dependency_ready ?? item.dependencies_ready ?? status.dependency_ready),
    accepted: bool(item.accepted ?? item.verified ?? status.accepted),
    missing_dependencies: Array.isArray(missing) ? missing.map(text).filter(Boolean) : [],
    acceptance_command: text(item.acceptance_command || item.verify_command || status.acceptance_command),
    callable_name: text(item.callable_name || item.entrypoint || item.callable),
    execution_boundary: text(item.execution_boundary || status.execution_boundary),
    routes: Array.isArray(item.routes) ? item.routes.map(text).filter(Boolean) : [],
    metadata: item,
  };
}

export async function fetchCatalog(): Promise<CatalogPayload> {
  const token = localStorage.getItem('reverseAnalyzerWebToken') || '';
  const headers: Record<string, string> = token ? { Authorization: 'Bearer ' + token } : {};
  const response = await fetch('/api/platform/catalog', { cache: 'no-store', headers });
  const body = await response.json() as Record<string, unknown>;
  if (!response.ok) {
    throw new Error(text(body.error) || '目录接口返回 ' + response.status);
  }

  const items: CatalogItem[] = [];
  if (Array.isArray(body.items)) {
    body.items.forEach((item, index) => items.push(normalizeItem(item, 'capability', index)));
  }
  const aliases: Record<CatalogKind, string[]> = {
    skill: ['skills'],
    tool: ['tools'],
    capability: ['capabilities', 'providers'],
    script: ['scripts'],
    dependency: ['dependencies', 'github_tools'],
    extension: ['extensions'],
  };
  for (const kind of KINDS) {
    for (const key of aliases[kind]) {
      const collection = body[key];
      if (Array.isArray(collection)) {
        collection.forEach((item, index) => items.push(normalizeItem(item, kind, index)));
      }
    }
  }
  if (Array.isArray(body.groups)) {
    body.groups.forEach((rawGroup) => {
      const group = rawGroup && typeof rawGroup === 'object' ? rawGroup as Record<string, unknown> : {};
      const groupKind = text(group.kind || group.type).toLowerCase() as CatalogKind;
      const kind = KINDS.includes(groupKind) ? groupKind : 'capability';
      if (Array.isArray(group.items)) {
        group.items.forEach((item, index) => items.push(normalizeItem(item, kind, index)));
      }
    });
  }
  return { generated_at: text(body.generated_at), items };
}
