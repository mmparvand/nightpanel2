import asyncio
import base64
import hashlib
import io
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

import paramiko
import yaml
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, validator
from sse_starlette.sse import EventSourceResponse

VERSION = "0.1.0"
ROOT_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = ROOT_DIR / "templates"
STATIC_DIR = ROOT_DIR / "static"


def scrub_sensitive(text: str) -> str:
    if not text:
        return text
    replacements = ["password", "passphrase", "private", "token", "secret"]
    clean = text
    for key in replacements:
        clean = clean.replace(key, "***")
        clean = clean.replace(key.capitalize(), "***")
        clean = clean.replace(key.upper(), "***")
    return clean


def sanitize_settings(payload: dict) -> dict:
    safe = {}
    for key, value in (payload or {}).items():
        if any(token in key.lower() for token in ["pass", "secret", "token"]):
            safe[key] = "***"
        else:
            safe[key] = value
    return safe


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self.hits: Dict[str, List[float]] = {}
        self.lock = asyncio.Lock()

    async def check(self, key: str):
        now = time.time()
        async with self.lock:
            events = self.hits.get(key, [])
            events = [ts for ts in events if ts > now - self.window]
            if len(events) >= self.limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                )
            events.append(now)
            self.hits[key] = events


class SSHPasswordAuth(BaseModel):
    type: str = Field("password", const=True)
    password: str


class SSHKeyAuth(BaseModel):
    type: str = Field("key", const=True)
    privateKey: str
    passphrase: Optional[str] = None


class ServerAuth(BaseModel):
    __root__: Union[SSHPasswordAuth, SSHKeyAuth]

    @property
    def value(self):
        return self.__root__

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value):
        if not isinstance(value, dict) or "type" not in value:
            raise ValueError("Invalid auth payload")
        auth_type = value.get("type")
        if auth_type == "password":
            return SSHPasswordAuth(**value)
        if auth_type == "key":
            return SSHKeyAuth(**value)
        raise ValueError("Unsupported auth type")


class ServerInfo(BaseModel):
    host: str
    port: int = Field(..., ge=1, le=65535)
    username: str
    auth: ServerAuth
    expectedFingerprint: Optional[str] = None


class TemplateSelection(BaseModel):
    id: str
    settings: Optional[dict] = Field(default_factory=dict)


class OfflineConfig(BaseModel):
    enabled: bool = False
    aptProxy: Optional[str] = None
    dockerRegistry: Optional[str] = None
    artifactMirror: Optional[str] = None


class RunRequest(BaseModel):
    server: ServerInfo
    templates: List[TemplateSelection]
    offline: OfflineConfig

    @validator("templates")
    def unique_templates(cls, v):
        seen = set()
        for tpl in v:
            if tpl.id in seen:
                raise ValueError(f"Duplicate template: {tpl.id}")
            seen.add(tpl.id)
        return v


def load_private_key(key_str: str, passphrase: Optional[str]):
    key_stream = io.StringIO(key_str)
    loaders = [
        paramiko.RSAKey.from_private_key,
        paramiko.Ed25519Key.from_private_key,
        paramiko.ECDSAKey.from_private_key,
    ]
    for loader in loaders:
        key_stream.seek(0)
        try:
            return loader(key_stream, password=passphrase)
        except paramiko.PasswordRequiredException:
            raise
        except Exception:
            continue
    raise ValueError("Unsupported private key format")


def format_fingerprint(host_key: paramiko.PKey) -> str:
    digest = hashlib.sha256(host_key.asbytes()).digest()
    return f"SHA256:{base64.b64encode(digest).decode()}"


def ssh_connect(server: ServerInfo) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    auth = server.auth.value
    kwargs = {
        "hostname": server.host,
        "port": server.port,
        "username": server.username,
        "timeout": 20,
        "look_for_keys": False,
        "allow_agent": False,
    }
    if isinstance(auth, SSHPasswordAuth):
        kwargs["password"] = auth.password
    else:
        kwargs["pkey"] = load_private_key(auth.privateKey, auth.passphrase)
    client.connect(**kwargs)
    return client


def run_ssh_command(client: paramiko.SSHClient, command: str) -> str:
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode().strip()
    error_output = stderr.read().decode().strip()
    if exit_status != 0:
        raise RuntimeError(f"{command} failed: {error_output}")
    return output


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def gather_preflight(client: paramiko.SSHClient) -> dict:
    try:
        os_info = run_ssh_command(client, "source /etc/os-release && echo ${PRETTY_NAME:-Linux}")
    except Exception:
        os_info = "Unknown"
    try:
        sudo_ok = run_ssh_command(client, "command -v sudo >/dev/null && echo yes || echo no")
        sudo_enabled = sudo_ok.strip() == "yes"
    except Exception:
        sudo_enabled = False
    try:
        cpu_cores = safe_int(run_ssh_command(client, "nproc || echo 1"), 1)
    except Exception:
        cpu_cores = 1
    try:
        ram_mb = safe_int(run_ssh_command(client, "free -m | awk '/Mem:/ {print $2}' || echo 0"), 0)
    except Exception:
        ram_mb = 0
    try:
        disk_gb = safe_int(
            run_ssh_command(client, "df -BG / | awk 'NR==2 {gsub(\"G\", \"\", $4); print $4}' || echo 0"),
            0,
        )
    except Exception:
        disk_gb = 0
    return {
        "os": os_info,
        "sudo": sudo_enabled,
        "cpuCores": cpu_cores,
        "ramMb": ram_mb,
        "diskFreeGb": disk_gb,
    }


def resolve_template_order(selected: List[str], registry: Dict[str, dict]) -> List[str]:
    resolved: List[str] = []
    visited = set()

    def visit(tid: str):
        if tid in visited:
            return
        visited.add(tid)
        tpl = registry.get(tid)
        if not tpl:
            raise ValueError(f"Template not found: {tid}")
        for req in tpl.get("requirements", []):
            visit(req)
        if tid not in resolved:
            resolved.append(tid)

    for tid in selected:
        visit(tid)
    return resolved


@dataclass
class LogEntry:
    ts: float
    level: str
    message: str
    progress: Optional[int] = None
    step: Optional[str] = None

    def to_event(self):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ts)),
            "level": self.level,
            "message": scrub_sensitive(self.message),
        }
        if self.progress is not None:
            payload["progress"] = self.progress
        if self.step:
            payload["step"] = self.step
        return payload


@dataclass
class RunRecord:
    id: str
    status: str = "queued"
    progress: int = 0
    currentStep: str = ""
    startedAt: Optional[float] = None
    finishedAt: Optional[float] = None
    outputs: dict = field(default_factory=dict)
    error: Optional[str] = None
    logs: List[LogEntry] = field(default_factory=list)
    watchers: List[asyncio.Queue] = field(default_factory=list)
    server: Optional[ServerInfo] = None

    def to_json(self):
        return {
            "id": self.id,
            "status": self.status,
            "progress": self.progress,
            "currentStep": self.currentStep,
            "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.startedAt))
            if self.startedAt
            else None,
            "finishedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.finishedAt))
            if self.finishedAt
            else None,
            "outputs": self.outputs,
            "error": self.error,
        }


class RunManager:
    def __init__(self):
        self.runs: Dict[str, RunRecord] = {}
        self.lock = asyncio.Lock()

    async def create_run(self, server: ServerInfo, templates: List[str]) -> RunRecord:
        run_id = secrets.token_hex(8)
        record = RunRecord(id=run_id, server=server)
        async with self.lock:
            self.runs[run_id] = record
        return record

    async def get(self, run_id: str) -> RunRecord:
        async with self.lock:
            if run_id not in self.runs:
                raise HTTPException(status_code=404, detail="Run not found")
            return self.runs[run_id]

    async def list_runs(self) -> List[RunRecord]:
        async with self.lock:
            return list(self.runs.values())

    async def add_log(self, run_id: str, entry: LogEntry):
        async with self.lock:
            run = self.runs.get(run_id)
            if not run:
                return
            run.logs.append(entry)
            queues = list(run.watchers)
        for q in queues:
            await q.put({"type": "log", "entry": entry})

    async def finish(self, run_id: str, status_text: str):
        async with self.lock:
            run = self.runs.get(run_id)
            if not run:
                return
            run.status = status_text
            run.finishedAt = time.time()
            queues = list(run.watchers)
        done_payload = {"type": "done", "status": status_text}
        for q in queues:
            await q.put(done_payload)

    async def update_progress(self, run_id: str, progress: int, step: str = ""):
        async with self.lock:
            run = self.runs.get(run_id)
            if not run:
                return
            run.progress = progress
            if step:
                run.currentStep = step


class TemplateRegistry:
    def __init__(self, directory: Path):
        self.directory = directory
        self.templates: Dict[str, dict] = {}
        self.refresh()

    def refresh(self):
        self.templates = {}
        for path in self.directory.glob("*"):
            if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
                continue
            with path.open() as f:
                data = yaml.safe_load(f)
                if data:
                    self.templates[data["id"]] = data

    def list(self):
        return list(self.templates.values())

    def get(self, template_id: str) -> dict:
        tpl = self.templates.get(template_id)
        if not tpl:
            raise HTTPException(status_code=404, detail="Template not found")
        return tpl


run_manager = RunManager()
template_registry = TemplateRegistry(TEMPLATES_DIR)
ssh_rate_limit = RateLimiter(limit=10, window_seconds=60)
run_rate_limit = RateLimiter(limit=5, window_seconds=60)
app = FastAPI(title="WarOps NightPanel", version=VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def rate_limit_dep(request: Request, limiter: RateLimiter):
    await limiter.check(client_ip(request))


async def limit_test_ssh(request: Request):
    await rate_limit_dep(request, ssh_rate_limit)


async def limit_run(request: Request):
    await rate_limit_dep(request, run_rate_limit)


@app.get("/", response_class=FileResponse)
async def serve_index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/admin", response_class=FileResponse)
async def serve_admin():
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/api/templates")
async def list_templates():
    template_registry.refresh()
    return template_registry.list()


@app.post("/api/test-ssh")
async def test_ssh(payload: ServerInfo, request: Request, _: None = Depends(limit_test_ssh)):
    try:
        client = ssh_connect(payload)
        transport = client.get_transport()
        host_key = transport.get_remote_server_key()
        fingerprint = format_fingerprint(host_key)
        if payload.expectedFingerprint and fingerprint != payload.expectedFingerprint:
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": "Fingerprint mismatch", "fingerprint": fingerprint},
            )
        preflight = gather_preflight(client)
        client.close()
        return {"ok": True, "fingerprint": fingerprint, "preflight": preflight}
    except HTTPException:
        raise
    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": str(exc)},
        )


def build_template_commands(template_id: str, settings: dict, offline: OfflineConfig) -> List[str]:
    safe_settings = sanitize_settings(settings or {})
    commands = []
    if template_id == "docker":
        commands.append("which docker || curl -fsSL https://get.docker.com | sh")
        commands.append("sudo systemctl enable --now docker")
    elif template_id == "nginx":
        commands.append("sudo apt-get update && sudo apt-get install -y nginx")
        if safe_settings.get("domain"):
            commands.append(f"echo 'Configuring nginx for {safe_settings.get('domain')}'")
    elif template_id == "marzban":
        commands.append(f"echo 'Deploying Marzban with Docker Compose (monitoring={safe_settings.get('enable_monitoring')})'")
    elif template_id == "3x-ui":
        commands.append(f"echo 'Installing 3x-ui panel for {safe_settings.get('admin_user', 'admin')}'")
    elif template_id == "hiddify":
        commands.append(f"echo 'Installing Hiddify suite (tls={safe_settings.get('enable_tls')})'")
    elif template_id == "rathole":
        commands.append(f"echo 'Setting up Rathole tunnel on port {safe_settings.get('server_port', 2333)}'")
    elif template_id == "cache-warmup":
        commands.append("echo 'Preparing offline caches'")
    else:
        commands.append(f"echo 'Running template {template_id}'")

    if offline.enabled:
        if offline.aptProxy:
            commands.insert(0, f"echo 'Acquire::http::Proxy \"{offline.aptProxy}\";' | sudo tee /etc/apt/apt.conf.d/01proxy")
        if offline.dockerRegistry:
            commands.append(
                f"echo '{{\"registry-mirrors\":[\"{offline.dockerRegistry}\"]}}' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker"
            )
        if offline.artifactMirror:
            commands.append(f"echo 'Using artifact mirror {offline.artifactMirror}'")
    return commands


async def execute_template_commands(
    client: paramiko.SSHClient,
    run_id: str,
    template_id: str,
    commands: List[str],
    total: int,
    index: int,
):
    step_label = f"{template_id}"
    for idx, cmd in enumerate(commands, start=1):
        progress = min(99, int(((index - 1) / total) * 100) + int(idx / max(len(commands), 1) * (100 / total)))
        await run_manager.update_progress(run_id, progress, step_label)
        await run_manager.add_log(run_id, LogEntry(ts=time.time(), level="info", message=f"[{template_id}] {cmd}", progress=progress, step=step_label))
        try:
            run_ssh_command(client, cmd)
            await run_manager.add_log(
                run_id,
                LogEntry(ts=time.time(), level="success", message=f"[{template_id}] completed: {cmd}", progress=progress, step=step_label),
            )
        except Exception as exc:
            await run_manager.add_log(
                run_id, LogEntry(ts=time.time(), level="error", message=f"[{template_id}] failed: {exc}", step=step_label)
            )
            raise


async def run_installation(record: RunRecord, registry: TemplateRegistry, selections: List[TemplateSelection], offline: OfflineConfig):
    run_id = record.id
    await run_manager.update_progress(run_id, 1, "initializing")
    await run_manager.add_log(run_id, LogEntry(ts=time.time(), level="info", message="Starting run", progress=1, step="initializing"))
    try:
        client = ssh_connect(record.server)
    except Exception as exc:
        record.status = "failed"
        record.error = str(exc)
        record.finishedAt = time.time()
        await run_manager.add_log(run_id, LogEntry(ts=time.time(), level="error", message=f"Connection failed: {exc}"))
        await run_manager.finish(run_id, "failed")
        return

    record.startedAt = time.time()
    record.status = "running"
    await run_manager.update_progress(run_id, 5, "connected")
    await run_manager.add_log(run_id, LogEntry(ts=time.time(), level="success", message="SSH connected", progress=5, step="connected"))

    selected_ids = [tpl.id for tpl in selections]
    try:
        full_order = resolve_template_order(selected_ids, registry.templates)
    except Exception as exc:
        record.status = "failed"
        record.error = str(exc)
        record.finishedAt = time.time()
        await run_manager.add_log(run_id, LogEntry(ts=time.time(), level="error", message=f"Resolution failed: {exc}"))
        await run_manager.finish(run_id, "failed")
        client.close()
        return

    total = len(full_order)
    outputs = {}

    for idx, template_id in enumerate(full_order, start=1):
        tpl_meta = registry.get(template_id)
        settings = next((sel.settings for sel in selections if sel.id == template_id), {}) or {}
        await run_manager.add_log(
            run_id,
            LogEntry(
                ts=time.time(),
                level="info",
                message=f"Running template {template_id}",
                progress=record.progress,
                step=template_id,
            ),
        )
        try:
            commands = build_template_commands(template_id, settings, offline)
            await execute_template_commands(client, run_id, template_id, commands, total, idx)
            outputs[template_id] = {
                "status": "done",
                "settingsApplied": sanitize_settings(settings),
                "ports": tpl_meta.get("ports", []),
            }
        except Exception as exc:
            record.status = "failed"
            record.error = str(exc)
            await run_manager.add_log(run_id, LogEntry(ts=time.time(), level="error", message=f"{template_id} failed: {exc}", step=template_id))
            await run_manager.finish(run_id, "failed")
            client.close()
            return

    record.status = "success"
    record.outputs = outputs
    await run_manager.update_progress(run_id, 100, "completed")
    await run_manager.add_log(run_id, LogEntry(ts=time.time(), level="success", message="Run completed", progress=100, step="completed"))
    record.finishedAt = time.time()
    await run_manager.finish(run_id, "success")
    client.close()


@app.post("/api/run")
async def start_run(payload: RunRequest, request: Request, background: BackgroundTasks, _: None = Depends(limit_run)):
    record = await run_manager.create_run(payload.server, [tpl.id for tpl in payload.templates])
    record.currentStep = "queued"
    background.add_task(run_installation, record, template_registry, payload.templates, payload.offline)
    return {"runId": record.id}


@app.get("/api/run/{run_id}")
async def get_run(run_id: str):
    record = await run_manager.get(run_id)
    return record.to_json()


@app.get("/api/run/{run_id}/stream")
async def stream_run(run_id: str):
    record = await run_manager.get(run_id)

    async def event_generator():
        backlog = [entry.to_event() for entry in record.logs]
        for entry in backlog:
            yield {"event": "log", "data": json.dumps(entry)}
        if record.status in {"success", "failed", "canceled"}:
            yield {"event": "done", "data": json.dumps({"status": record.status})}
            return
        queue: asyncio.Queue = asyncio.Queue()
        record.watchers.append(queue)
        try:
            while True:
                event = await queue.get()
                if event["type"] == "log":
                    yield {"event": "log", "data": json.dumps(event["entry"].to_event())}
                elif event["type"] == "done":
                    yield {"event": "done", "data": json.dumps({"status": event.get("status", "success")})}
                    break
        finally:
            if queue in record.watchers:
                record.watchers.remove(queue)

    return EventSourceResponse(event_generator())


@app.post("/api/run/{run_id}/cancel")
async def cancel_run(run_id: str):
    record = await run_manager.get(run_id)
    if record.status in {"success", "failed", "canceled"}:
        return {"status": record.status}
    record.status = "canceled"
    record.finishedAt = time.time()
    await run_manager.finish(run_id, "canceled")
    return {"status": "canceled"}


@app.get("/api/run/{run_id}/logs", response_class=PlainTextResponse)
async def download_logs(run_id: str):
    record = await run_manager.get(run_id)
    lines = []
    for log in record.logs:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(log.ts))
        lines.append(f"{ts} [{log.level}] {scrub_sensitive(log.message)}")
    return "\n".join(lines)


@app.get("/api/runs")
async def list_runs():
    runs = await run_manager.list_runs()
    return [r.to_json() for r in runs]


@app.get("/api/admin/info")
async def admin_info():
    uptime_seconds = time.time() - psutil_boot_time()
    return {"version": VERSION, "uptimeSeconds": int(uptime_seconds)}


def psutil_boot_time() -> float:
    try:
        import psutil

        return psutil.boot_time()
    except Exception:
        try:
            with open("/proc/uptime") as f:
                uptime_seconds = float(f.read().split()[0])
                return time.time() - uptime_seconds
        except Exception:
            return time.time()


def run():
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.environ.get("WAROPS_HOST", "0.0.0.0"),
        port=int(os.environ.get("WAROPS_PORT", "8088")),
        reload=bool(os.environ.get("WAROPS_RELOAD", "False").lower() == "true"),
    )


if __name__ == "__main__":
    run()
