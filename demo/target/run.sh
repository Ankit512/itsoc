#!/usr/bin/env bash
# ==============================================================================
# run.sh — provisions and starts the disposable ITSOC demo target container.
#
# BINDING GUARDRAILS (hive/stage-c/GUARDRAILS.md):
# 1. LOOPBACK ONLY: SSH published to 127.0.0.1:2222 ONLY (never 0.0.0.0).
# 2. NEVER --net=host: Container gets its own isolated network namespace.
# 3. NO DOCKER SOCKET OR HOST FS MOUNTS: Socket access forbidden.
# 4. CAP-ADD ONLY: --cap-add=NET_ADMIN only (never --privileged).
# 5. PRIVATE KEY SAFETY: Private key NEVER enters image, container, or logs.
#    Only public key is mounted read-only as /root/.ssh/authorized_keys:ro.
# ==============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
KEY_DIR="$REPO_ROOT/console/.soc/keys"
KEY_PATH="$KEY_DIR/target_ed25519"
PUB_KEY_PATH="$KEY_DIR/target_ed25519.pub"
IMAGE_NAME="itsoc-demo-target"
CONTAINER_NAME="itsoc-demo-target"
PORT="2222"

echo "=== ITSOC Demo Target Provisioner ==="

# 1. Verify Docker CLI and Daemon
if ! command -v docker >/dev/null 2>&1; then
    echo "[ERROR] docker CLI not found."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "[BLOCKED] Docker daemon is not running (docker info failed)."
    echo "          Please start Docker Desktop / daemon for live container execution."
    exit 2
fi

# 2. Key Management (private key stays on host under console/.soc/keys)
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

if [ ! -f "$KEY_PATH" ]; then
    echo "Generating Ed25519 keypair for demo target..."
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "itsoc-demo-target"
    chmod 600 "$KEY_PATH"
    chmod 644 "$PUB_KEY_PATH"
    echo "Key generated: $KEY_PATH (private) / $PUB_KEY_PATH (public)"
fi

# 3. Build Docker Image
echo "Building $IMAGE_NAME..."
docker build -t "$IMAGE_NAME" "$HERE"

# 4. Remove previous container if running
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Removing existing container $CONTAINER_NAME..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

# 5. Start Container with strict security constraints
echo "Starting container on 127.0.0.1:$PORT..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --cap-add=NET_ADMIN \
    -p 127.0.0.1:"$PORT":22 \
    -v "$PUB_KEY_PATH":/root/.ssh/authorized_keys:ro \
    "$IMAGE_NAME"

echo "=== Container $CONTAINER_NAME running on 127.0.0.1:$PORT ==="
echo "Connect via: ssh -i $KEY_PATH -p $PORT root@127.0.0.1"
