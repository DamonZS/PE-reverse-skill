#!/bin/sh
set -eu

ROOT="${CODEGRAPH_ROOT:-/opt/codebase-memory}"
RELEASE_DIR="${1:?release directory is required}"
ARCHIVE="codebase-memory-mcp-ui-linux-amd64-portable.tar.gz"

install -d -m 0750 "$ROOT/bin" "$ROOT/data" "$ROOT/repositories"
tmp="$(mktemp -d "$ROOT/.install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
cp "$RELEASE_DIR/$ARCHIVE" "$tmp/$ARCHIVE"
cp "$RELEASE_DIR/codegraph-checksums.txt" "$tmp/checksums.txt"
(cd "$tmp" && grep "  $ARCHIVE\$" checksums.txt | sha256sum -c -)
tar -xzf "$tmp/$ARCHIVE" -C "$tmp"
binary="$(find "$tmp" -type f -name codebase-memory-mcp | head -n 1)"
test -n "$binary"
install -m 0755 "$binary" "$ROOT/bin/codebase-memory-mcp"

test -s "$RELEASE_DIR/source.tar.gz"
next="$ROOT/repositories/pe-reverse-analyzer.next"
rm -rf "$next"
install -d -m 0750 "$next"
tar -xzf "$RELEASE_DIR/source.tar.gz" -C "$next"
rm -rf "$ROOT/repositories/pe-reverse-analyzer.previous"
if [ -d "$ROOT/repositories/pe-reverse-analyzer" ]; then
  mv "$ROOT/repositories/pe-reverse-analyzer" "$ROOT/repositories/pe-reverse-analyzer.previous"
fi
mv "$next" "$ROOT/repositories/pe-reverse-analyzer"

if ! id codegraph >/dev/null 2>&1; then
  useradd --system --home-dir "$ROOT" --shell /usr/sbin/nologin codegraph
fi
chown -R codegraph:codegraph "$ROOT"
install -o root -g root -m 0644 "$RELEASE_DIR/deploy/codebase-memory.service" /etc/systemd/system/codebase-memory.service

auth_file=/etc/nginx/snippets/codegraph-auth.conf
if [ ! -s "$ROOT/bearer-token" ]; then
  umask 077
  openssl rand -hex 32 > "$ROOT/bearer-token"
fi
token="$(cat "$ROOT/bearer-token")"
install -d -m 0755 /etc/nginx/snippets
printf 'if ($http_authorization != "Bearer %s") { return 401; }\n' "$token" > "$auth_file"
chmod 0600 "$auth_file"

systemctl daemon-reload
systemctl enable --now codebase-memory.service
systemctl restart codebase-memory.service
for i in $(seq 1 30); do
  curl -fsS http://127.0.0.1:9749/ >/dev/null && break
  test "$i" -lt 30
  sleep 1
done
curl -fsS -X POST -H 'Content-Type: application/json' \
  --data '{"root_path":"/opt/codebase-memory/repositories/pe-reverse-analyzer","project_name":"pe-reverse-analyzer-main"}' \
  http://127.0.0.1:9749/api/index >/dev/null
