#!/usr/bin/env bash
set -euo pipefail

output="dist/reverse-jailbreak"
clean=0
no_build_isolation=0
source_date_epoch="${SOURCE_DATE_EPOCH:-}"

usage() {
  cat <<'EOF'
Usage: build_reverse_jailbreak.sh [options]
  --output DIR              release directory (default: dist/reverse-jailbreak)
  --clean                   remove the output directory first
  --no-build-isolation      use the installed build backend
  --source-date-epoch SEC   reproducible wheel timestamp (>= 315532800)
  -h, --help                show this help
EOF
}

while (($#)); do
  case "$1" in
    --output) [[ $# -ge 2 ]] || { echo "--output needs a value" >&2; exit 2; }; output="$2"; shift 2 ;;
    --clean) clean=1; shift ;;
    --no-build-isolation) no_build_isolation=1; shift ;;
    --source-date-epoch) [[ $# -ge 2 ]] || { echo "--source-date-epoch needs a value" >&2; exit 2; }; source_date_epoch="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$source_date_epoch" ]] && command -v git >/dev/null 2>&1; then
  source_date_epoch="$(git log -1 --format=%ct 2>/dev/null || true)"
fi
if [[ -z "$source_date_epoch" ]]; then
  source_date_epoch=315532800
fi
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || { echo "SOURCE_DATE_EPOCH must be an integer Unix timestamp" >&2; exit 2; }
(( source_date_epoch >= 315532800 )) || { echo "source date epoch must be at or after 1980-01-01" >&2; exit 2; }
export SOURCE_DATE_EPOCH="$source_date_epoch"

if (( clean )); then
  rm -rf -- "$output"
fi
mkdir -p -- "$output"

wheel_args=(-m pip wheel . --no-deps --wheel-dir "$output")
if (( no_build_isolation )); then
  wheel_args+=(--no-build-isolation)
fi
python "${wheel_args[@]}"

version="$(python -c 'from reverse_analyzer._version import __version__; print(__version__)')"
release_notes="docs/releases/${version}.md"
[[ -f "$release_notes" ]] || { echo "missing release notes for package version: $release_notes" >&2; exit 1; }
cp -- schemas/jailbreak-campaign.schema.json "$output/"
cp -- config/jailbreak-campaign.example.json "$output/"
cp -- docs/reverse_jailbreak_release.md "$output/"
cp -- CHANGELOG.md "$output/"
cp -- "$release_notes" "$output/RELEASE_NOTES.md"
cp -- scripts/smoke_reverse_jailbreak_release.py "$output/smoke_release.py"
python -m reverse_analyzer.llm_jailbreak.release sbom "$output"
python -m reverse_analyzer.llm_jailbreak.release build "$output"
python -m reverse_analyzer.llm_jailbreak.release verify "$output"
[[ -f "$output/release-manifest.json" ]] || {
  echo "release-manifest.json was not generated" >&2
  exit 1
}
printf 'Portable package written to %s\n' "$output"
