#!/bin/bash
set -e

# Track errors
ERRORS=()

# Helper functions
echo_section() {
  echo -e "\n\033[1;34m$1\033[0m"
}

handle_error() {
  ERRORS+=("$1")
  echo -e "\033[1;31m[ERROR]\033[0m $1"
}

# 1. Check/install Python 3 and pip
if ! command -v python3 &>/dev/null; then
  echo_section "Installing Python 3..."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install python || handle_error "Failed to install Python 3 via Homebrew."
  else
    sudo apt-get update && sudo apt-get install -y python3 python3-pip || handle_error "Failed to install Python 3 via apt."
  fi
fi

if ! command -v pip3 &>/dev/null; then
  echo_section "Installing pip3..."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install pipx || handle_error "Failed to install pipx via Homebrew."
    pipx ensurepath || handle_error "Failed to ensure pipx path."
  else
    sudo apt-get install -y python3-pip || handle_error "Failed to install pip3 via apt."
  fi
fi

# 2. Install Python dependencies
cd "$(dirname "$0")"
echo_section "Installing Python dependencies..."
pip3 install --user fastapi uvicorn pydantic python-dotenv || handle_error "Failed to install Python dependencies."

# 3. Start FastAPI backend in background
if pgrep -f "uvicorn backend.main:app" >/dev/null; then
  echo_section "FastAPI backend already running."
else
  echo_section "Starting FastAPI backend..."
  nohup python3 -m uvicorn backend.main:app --reload --port 8000 > backend.log 2>&1 &
  sleep 2
fi

# 4. Check/install Node.js and npm
if ! command -v node &>/dev/null; then
  echo_section "Installing Node.js..."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install node || handle_error "Failed to install Node.js via Homebrew."
  else
    sudo apt-get install -y nodejs npm || handle_error "Failed to install Node.js/npm via apt."
  fi
fi

# 5. Install frontend dependencies and start React dashboard
cd frontend-dashboard
echo_section "Installing frontend dependencies..."
npm install || handle_error "Failed to install frontend dependencies."
if pgrep -f "react-scripts start" >/dev/null; then
  echo_section "React frontend already running."
else
  echo_section "Starting React frontend..."
  nohup npm start > ../frontend.log 2>&1 &
  sleep 2
fi
cd ..

# 6. Check/install Grafana
if ! command -v grafana-server &>/dev/null; then
  echo_section "Installing Grafana..."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    brew install grafana || handle_error "Failed to install Grafana via Homebrew."
  else
    sudo apt-get install -y apt-transport-https software-properties-common wget || handle_error "Failed to install Grafana prerequisites."
    wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add - || handle_error "Failed to add Grafana GPG key."
    echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
    sudo apt-get update && sudo apt-get install -y grafana || handle_error "Failed to install Grafana via apt."
  fi
fi

# 7. Install Infinity plugin and restart Grafana
PLUGIN_INSTALLED=0
PLUGIN_CMD="grafana-cli plugins install yesoreyeram-infinity-datasource"
PLUGIN_DIR="/usr/local/var/lib/grafana/plugins"

if grafana-cli plugins ls | grep -q yesoreyeram-infinity-datasource; then
  echo_section "Grafana Infinity plugin already installed."
  PLUGIN_INSTALLED=1
else
  echo_section "Installing Grafana Infinity plugin..."
  if [ -w "$PLUGIN_DIR" ]; then
    $PLUGIN_CMD || handle_error "Failed to install Infinity plugin (direct)."
  else
    sudo $PLUGIN_CMD || handle_error "Failed to install Infinity plugin (sudo)."
  fi
  if grafana-cli plugins ls | grep -q yesoreyeram-infinity-datasource; then
    PLUGIN_INSTALLED=1
  else
    handle_error "Infinity plugin install did not complete successfully."
  fi
fi

if [[ "$OSTYPE" == "darwin"* ]]; then
  brew services restart grafana || handle_error "Failed to restart Grafana via Homebrew."
else
  sudo systemctl restart grafana-server || handle_error "Failed to restart Grafana via systemctl."
fi

# 8. Print instructions for dashboard import
cat <<EOF

\033[1;32mSetup complete!\033[0m

- FastAPI backend:     http://localhost:8000
- React dashboard:     http://localhost:3000
- Grafana:             http://localhost:3000 (default user: admin / admin)

Next steps:
1. Log in to Grafana and add the 'Infinity' data source (point to your FastAPI endpoints).
2. Import the following dashboard JSON (replace <ALERT_ID> with a real alert ID):

---
{
  "dashboard": {
    "id": null,
    "title": "Risky Sign-In SOC Investigation",
    "panels": [
      {
        "type": "table",
        "title": "Risky Sign-In Alerts",
        "datasource": "Infinity",
        "targets": [
          {
            "type": "json",
            "url": "http://localhost:8000/alerts/risky-signin",
            "format": "json"
          }
        ],
        "columns": [
          { "text": "id", "type": "string" },
          { "text": "type", "type": "string" },
          { "text": "status", "type": "string" },
          { "text": "assigned_to", "type": "string" },
          { "text": "created_at", "type": "string" },
          { "text": "updated_at", "type": "string" }
        ],
        "gridPos": { "h": 8, "w": 24, "x": 0, "y": 0 }
      },
      {
        "type": "table",
        "title": "Playbook Steps (First Alert)",
        "datasource": "Infinity",
        "targets": [
          {
            "type": "json",
            "url": "http://localhost:8000/playbook/risky-signin/<ALERT_ID>",
            "format": "json"
          }
        ],
        "columns": [
          { "text": "id", "type": "string" },
          { "text": "description", "type": "string" },
          { "text": "checked", "type": "boolean" },
          { "text": "automated", "type": "boolean" },
          { "text": "approval_required", "type": "boolean" },
          { "text": "approved", "type": "boolean" },
          { "text": "timestamp", "type": "string" },
          { "text": "analyst", "type": "string" }
        ],
        "gridPos": { "h": 8, "w": 24, "x": 0, "y": 8 }
      }
    ],
    "schemaVersion": 30,
    "version": 1
  }
}
---

3. For interactive playbook step updates, use the Grafana Form Panel or a custom plugin to POST to the backend endpoints.

EOF

# Print summary of errors if any
if [ ${#ERRORS[@]} -ne 0 ]; then
  echo -e "\n\033[1;31mSome steps failed. Please review the errors above and address them manually.\033[0m"
  for err in "${ERRORS[@]}"; do
    echo -e "- $err"
  done
else
  echo -e "\n\033[1;32mAll steps completed successfully!\033[0m"
fi 