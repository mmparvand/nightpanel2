#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/yourusername/nightpanel2.git}"
INSTALL_DIR="/opt/warops"
SERVICE_NAME="warops"
ENV_FILE="/etc/warops.env"

echo "[+] Updating system packages..."
apt-get update -y
apt-get install -y python3 python3-venv git curl

if [ ! -d "$INSTALL_DIR" ]; then
  echo "[+] Creating install directory at $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
fi

if [ ! -d "$INSTALL_DIR/.git" ]; then
  echo "[+] Cloning repository"
  git clone "$REPO_URL" "$INSTALL_DIR"
else
  echo "[+] Updating existing repository"
  git -C "$INSTALL_DIR" fetch --all
  git -C "$INSTALL_DIR" reset --hard origin/main || true
fi

cd "$INSTALL_DIR"

if [ ! -d "venv" ]; then
  echo "[+] Creating virtual environment"
  python3 -m venv venv
fi

echo "[+] Installing dependencies"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

if [ ! -f "$ENV_FILE" ]; then
  cat <<EOF > "$ENV_FILE"
# WarOps environment overrides
WAROPS_HOST=0.0.0.0
WAROPS_PORT=8088
EOF
fi

echo "[+] Writing systemd service"
cat <<EOF > /etc/systemd/system/${SERVICE_NAME}.service
[Unit]
Description=WarOps NightPanel
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn app.main:app --host \${WAROPS_HOST} --port \${WAROPS_PORT}
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "[+] Enabling service"
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
IP=${IP:-"localhost"}
PORT=$(grep WAROPS_PORT ${ENV_FILE} | cut -d'=' -f2 | head -n1)
PORT=${PORT:-8088}

echo "--------------------------------------"
echo "User Panel:  http://${IP}:${PORT}/"
echo "Admin Panel: http://${IP}:${PORT}/admin"
echo "--------------------------------------"
