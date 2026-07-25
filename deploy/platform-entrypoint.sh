#!/bin/sh
set -eu

read_secret() {
  variable="$1"
  file_variable="${variable}_FILE"
  eval "file_path=\${$file_variable:-}"
  if [ -n "${file_path:-}" ]; then
    if [ ! -r "$file_path" ]; then
      echo "secret file for $variable is unreadable" >&2
      exit 64
    fi
    value=$(cat "$file_path")
    export "$variable=$value"
  fi
}

read_secret REVERSE_ANALYZER_WEB_TOKEN
read_secret REVERSE_ANALYZER_GITHUB_CLIENT_SECRET
read_secret REVERSE_ANALYZER_GOOGLE_CLIENT_SECRET
read_secret REVERSE_ANALYZER_POSTGRES_PASSWORD

if [ -z "${REVERSE_ANALYZER_DATABASE_URL:-}" ] && [ -n "${REVERSE_ANALYZER_POSTGRES_PASSWORD:-}" ]; then
  export REVERSE_ANALYZER_DATABASE_URL="$(python -c 'import os, urllib.parse; print("postgres://%s:%s@%s:%s/%s?sslmode=disable" % (urllib.parse.quote(os.environ["REVERSE_ANALYZER_POSTGRES_USER"], safe=""), urllib.parse.quote(os.environ["REVERSE_ANALYZER_POSTGRES_PASSWORD"], safe=""), os.environ["REVERSE_ANALYZER_POSTGRES_HOST"], os.environ.get("REVERSE_ANALYZER_POSTGRES_PORT", "5432"), urllib.parse.quote(os.environ["REVERSE_ANALYZER_POSTGRES_DB"], safe="")))')"
fi
unset REVERSE_ANALYZER_POSTGRES_PASSWORD

exec reverse-analyzer-server "$@"
