# WarOps NightPanel

FastAPI-based installer panel with user wizard and admin dashboard. No database is used; all runs are in-memory.

## Quick install (Ubuntu 20.04+)

```bash
curl -fsSL https://raw.githubusercontent.com/yourusername/nightpanel2/main/install.sh | sudo bash
```

Set `REPO_URL` to your repository before running if needed:

```bash
REPO_URL=https://github.com/yourusername/nightpanel2.git bash install.sh
```

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8088
```

Open `http://localhost:8088/` for the user wizard and `/admin` for the admin view.
