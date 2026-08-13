#!/bin/bash
# BurpSuite MCP Full Control - Linux / macOS Build Script
# Requires: JDK 21+, curl
# Produces: build/libs/burp-mcp-full.jar (fat jar, Burp-loadable)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ===== Auto-detect JAVA_HOME =====
if [ -z "$JAVA_HOME" ]; then
    if command -v javac >/dev/null 2>&1; then
        JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
    else
        echo "ERROR: javac not found. Install JDK 21+ or set JAVA_HOME."
        exit 1
    fi
fi
JAVAC="$JAVA_HOME/bin/javac"
JAR="$JAVA_HOME/bin/jar"

if ! "$JAVAC" -version 2>/dev/null | grep -qE '(1\.)?(2[1-9]|[3-9][0-9])'; then
    echo "WARNING: JDK 21+ recommended. Detected: $("$JAVAC" -version 2>&1)"
fi

SRC="src/main/java/com/burpmcp"
RES="src/main/resources"
LIB="lib"
OUT="build/classes"
DIST="build/libs"
MONTOYA="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2025.5/montoya-api-2025.5.jar"
GSON="https://repo1.maven.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar"
NANO="https://repo1.maven.org/maven2/org/nanohttpd/nanohttpd/2.3.1/nanohttpd-2.3.1.jar"

echo "[1/4] Downloading dependencies..."
mkdir -p "$LIB"
[ -f "$LIB/montoya-api.jar" ] || curl -sL -o "$LIB/montoya-api.jar" "$MONTOYA"
[ -f "$LIB/gson.jar" ]        || curl -sL -o "$LIB/gson.jar"        "$GSON"
[ -f "$LIB/nanohttpd.jar" ]   || curl -sL -o "$LIB/nanohttpd.jar"   "$NANO"

echo "[2/4] Compiling..."
mkdir -p "$OUT"
"$JAVAC" --release 21 -encoding UTF-8 -cp "$LIB/montoya-api.jar:$LIB/gson.jar:$LIB/nanohttpd.jar" -d "$OUT" "$SRC"/*.java

# Copy resources (extension descriptor) so the jar is loadable by Burp
cp -r "$RES/META-INF" "$OUT/"

echo "[3/4] Packaging fat jar..."
mkdir -p "$DIST"
cd "$OUT"
"$JAR" xf "../../$LIB/gson.jar" com
"$JAR" xf "../../$LIB/nanohttpd.jar" fi
cd ../..
"$JAR" cf "$DIST/burp-mcp-full.jar" -C "$OUT" .

echo "[4/4] Done!"
echo "Output: $DIST/burp-mcp-full.jar"
echo ""
echo "Install: Burp Suite -> Extensions -> Add -> Java -> Select $DIST/burp-mcp-full.jar"
echo ""
echo "MCP config (any client):"
echo "  { \"command\": \"node\", \"args\": [\"$SCRIPT_DIR/mcp-bridge.js\"] }"
