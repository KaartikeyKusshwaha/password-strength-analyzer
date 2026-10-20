"""SentinelOps: small-team exposure triage and reviewed remediation."""
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlsplit

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import agents, scanner
from .security import consume_factor, digest, hash_password, password_policy, verify_password, check_totp
from .store import Store, canonical, now, uid
from .sharing import TeamPayload
from .vault_activity import record_connection_revocations, record_action_cancellations, invalidate_ownership
from .posture import Report as PostureReport

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


class Settings:
    def __init__(self, data_dir=None, origin=None, groq_key=None, model=None, scan_hosts=None):
        self.data_dir = Path(data_dir or os.getenv("DATA_DIR", ROOT / "data"))
        self.origin = (origin or os.getenv("APP_ORIGIN", "http://127.0.0.1:8110")).rstrip("/")
        parsed = urlsplit(self.origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("APP_ORIGIN must be an HTTP(S) origin without path or credentials.")
        self.secure = parsed.scheme == "https"
        if not self.secure and parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("Public access requires HTTPS in APP_ORIGIN.")
        self.host = parsed.hostname
        self.groq_key = os.getenv("GROQ_API_KEY", "") if groq_key is None else groq_key
        self.model = model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.scan_hosts = {scanner.validate_host(h) for h in (scan_hosts if scan_hosts is not None else os.getenv("SCAN_HOSTS", "").split(",")) if h.strip()}


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Credentials(Body):
    email: str = Field(min_length=3, max_length=254)
    password: SecretStr
    token: SecretStr = SecretStr("")
    code: str = Field(default="", max_length=80)
    workspace_name: str = Field(default="My security workspace", min_length=2, max_length=70)

    @field_validator("email")
    @classmethod
    def email_valid(cls, value):
        import re
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter an email address.")
        return value.lower()


class Code(Body):
    code: str = Field(min_length=6, max_length=80)


class Reauth(Body):
    password: SecretStr
    code: str = Field(default="", max_length=80)


class Invite(Body):
    email: str = Field(min_length=3, max_length=254)
    role: Literal["analyst", "reviewer", "viewer"]


class Workspace(Body):
    name: str = Field(min_length=2, max_length=70)


class Asset(Body):
    name: str = Field(min_length=2, max_length=80)
    kind: Literal["application", "website", "mailbox", "service", "device"]
    owner: str = Field(min_length=2, max_length=80)
    environment: Literal["production", "staging", "development"]
    criticality: Literal["critical", "high", "medium", "low"]
    hostname: str = Field(default="", max_length=253)
    authorized: bool


class Scan(Body):
    asset_id: str
    kind: Literal["python", "dependencies", "email", "website"]
    label: str = Field(min_length=2, max_length=100)
    content: SecretStr = SecretStr("")
    format: Literal["requirements", "package-json"] = "requirements"
    authorized: bool


class Task(Body):
    finding_id: str
    assignee: str
    due: str = Field(default="", max_length=10)


class TaskUpdate(Body):
    action: Literal["start", "submit", "approve", "reject"]
    evidence: str = Field(default="", max_length=3000)


class Investigation(Body):
    title: str = Field(min_length=3, max_length=120)
    finding_ids: list[str] = Field(min_length=1, max_length=20)
    note: str = Field(default="", max_length=3000)


class InvestigationUpdate(Body):
    note: str = Field(min_length=5, max_length=3000)
    status: Literal["open", "investigating", "closed"]


class AgentRequest(Body):
    finding_ids: list[str] = Field(min_length=1, max_length=20)
    mode: Literal["triage", "remediation", "investigation"]
    create_tasks: bool = False
    create_investigation: bool = False


class OperationRequest(Body):
    action: Literal["device", "posture", "website", "python", "dependencies", "email"]
    target: str = Field(default="127.0.0.1", min_length=1, max_length=253)
    ports: list[int] = Field(default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5000, 8000, 8080, 8443], min_length=1, max_length=64)
    content: SecretStr = SecretStr("")
    format: Literal["requirements", "package-json"] = "requirements"
    authorized: bool
    ai_triage: bool = False
    device_id: str = Field(default="local", min_length=1, max_length=60)


class DeviceConnection(Reauth):
    label: str = Field(min_length=2, max_length=60)
    targets: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"], min_length=1, max_length=16)
    allow_posture: bool = False


class DeviceObservation(Body):
    host: str = Field(max_length=60)
    port: int = Field(ge=1, le=65535)
    status: Literal["open", "closed", "unassessed"]


class DeviceResult(Body):
    operation_id: str = Field(max_length=60)
    lease: SecretStr
    observations: list[DeviceObservation] = Field(min_length=0, max_length=64)
    posture: PostureReport | None = None


class DevicePoll(Body):
    version: Literal[1,2] = 1
    posture_enabled: bool = False


class VaultEnvelope(Body):
    version: Literal[1]
    salt: str
    iv: str
    ciphertext: str = Field(min_length=24, max_length=125000)

    @field_validator("salt", "iv", "ciphertext")
    @classmethod
    def valid_base64(cls, value, info):
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError:
            raise ValueError("Invalid envelope")
        if (info.field_name == "salt" and len(decoded) != 16) or (info.field_name == "iv" and len(decoded) != 12) or (info.field_name == "ciphertext" and len(decoded) < 16):
            raise ValueError("Invalid envelope")
        return value


class ArgonParameters(Body):
    algorithm: Literal['argon2id']
    memory_kib: Literal[65536]
    iterations: Literal[3]
    parallelism: Literal[1]


class VaultEnvelopeV2(VaultEnvelope):
    version: Literal[2]
    context: str = Field(pattern=r'^[a-f0-9]{24}$')
    kdf: ArgonParameters
    wrap_iv: str = Field(max_length=16)
    wrapped_key: str = Field(max_length=64)

    @field_validator('wrap_iv','wrapped_key')
    @classmethod
    def valid_wrap(cls, value, info):
        try:
            raw = base64.b64decode(value,validate=True)
        except ValueError:
            raise ValueError('Invalid wrapped key')
        if len(raw) != (12 if info.field_name == 'wrap_iv' else 48):
            raise ValueError('Invalid wrapped key length')
        return value


class VaultWrite(Body):
    revision: int = Field(ge=0)
    envelope: VaultEnvelope | VaultEnvelopeV2 = Field(discriminator='version')


class CompanionWrite(Body):
    revision: int = Field(ge=0)
    envelope: VaultEnvelope | VaultEnvelopeV2 | TeamPayload


class PairRequest(Reauth):
    kind: Literal['personal','shared'] = 'personal'
    label: str = Field(min_length=2, max_length=60)
    vault_id: str = Field(default="", max_length=60)


class VaultProperties(Body):
    name: str = Field(min_length=2, max_length=60)
    purpose: Literal["personal", "work", "project", "recovery"] = "personal"
    color: Literal["moss", "blue", "purple", "amber"] = "moss"
    lock_seconds: int = Field(default=180, ge=30, le=900)
    browser_enabled: bool = True
    browser_save: bool = True
    browser_fill: bool = True
    origins: list[str] = Field(default_factory=list, max_length=30)
    archived: bool = False
    is_default: bool = False

    @field_validator("origins")
    @classmethod
    def exact_origins(cls, values):
        result=[]
        for value in values:
            parsed=urlsplit(value)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {'','/'} or parsed.query or parsed.fragment:
                raise ValueError('Use exact HTTPS origins without credentials, paths or queries.')
            result.append(value.rstrip('/'))
        return list(dict.fromkeys(result))


class PortObservation(Body):
    host: Literal["127.0.0.1", "::1"]
    port: int = Field(ge=1, le=65535)
    status: Literal["open", "closed", "unassessed"]


class DeviceReport(Body):
    version: Literal[1]
    generated_at: str = Field(max_length=50)
    scope: Literal["fixed-loopback-tcp"]
    observations: list[PortObservation] = Field(min_length=1, max_length=60)


class DeviceImport(Body):
    asset_id: str
    report: DeviceReport
    authorized: bool


def must(value, message="Record not found", code=404):
    if not value:
        raise HTTPException(code, message)
    return value


def create_app(settings=None):
    settings = settings or Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(settings.data_dir / "sentinelops.db")
    key_path = settings.data_dir / ".encryption-key"
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
        key_path.chmod(0o600)
    cipher = Fernet(key_path.read_bytes().strip())
    bootstrap_path = settings.data_dir / ".bootstrap-token"
    with store.connect() as c:
        first_run = not c.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if first_run and not bootstrap_path.exists():
        bootstrap_path.write_text(secrets.token_urlsafe(32), encoding="utf-8")
        bootstrap_path.chmod(0o600)
    dummy_password = hash_password(secrets.token_urlsafe(24))
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sentinel-agent")

    @asynccontextmanager
    async def lifespan(app):
        with store.connect(write=True) as c:
            # Older installations offered fictional spaces. Hide those and move
            # existing sessions back to a real membership without deleting vaults.
            c.execute("UPDATE sessions SET workspace=(SELECT m.workspace FROM members m JOIN workspaces w ON m.workspace=w.id WHERE m.user=sessions.user AND w.demo=0 ORDER BY m.rowid LIMIT 1) WHERE workspace IN (SELECT id FROM workspaces WHERE demo=1) AND EXISTS(SELECT 1 FROM members m JOIN workspaces w ON m.workspace=w.id WHERE m.user=sessions.user AND w.demo=0)")
            for row in c.execute("SELECT workspace,kind,data FROM entities WHERE kind IN ('jobs','operations')").fetchall():
                job = json.loads(row["data"])
                if job["status"] in {"queued", "running"} and not (row["kind"] == "operations" and job.get("device_id", "local") != "local" and job["status"] == "queued"):
                    job.update(status="interrupted", error="Server restarted. Run again explicitly; no automatic replay.")
                    Store.put(c, row["workspace"], row["kind"], job)
        app.state.watch_service.start()
        try:
            yield
        finally:
            app.state.watch_service.stop()
            executor.shutdown(wait=True, cancel_futures=True)

    app = FastAPI(title="SentinelOps", version="0.13.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.settings = store, settings
    app.state.cipher, app.state.executor = cipher, executor
    app.state.agent_transport = None
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[settings.host, "localhost", "127.0.0.1", "testserver"] if settings.host in {"127.0.0.1", "localhost"} else [settings.host])

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default JSON includes the rejected input, possibly a password.
        return JSONResponse({"detail": "Invalid request. Check required fields, types and length limits."}, status_code=422)

    @app.middleware("http")
    async def boundary(request, call_next):
        companion = bool(re.fullmatch(r'/api/companion/(vault|actions(?:/[a-f0-9]{24}/(?:claim|result))?)',request.url.path))
        extension_origin = request.headers.get("origin", "")
        extension_origin_valid = bool(re.fullmatch(r"chrome-extension://[a-p]{32}", extension_origin))
        if companion and request.method == "OPTIONS":
            if not extension_origin_valid:
                return JSONResponse({"detail": "Extension origin required"}, status_code=403)
            return Response(status_code=204, headers={"Access-Control-Allow-Origin": extension_origin, "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Authorization, Content-Type", "Vary": "Origin"})
        if request.method in {"POST", "PATCH", "PUT", "DELETE"}:
            origin = request.headers.get("origin")
            if origin and origin != settings.origin and not (companion and extension_origin_valid):
                return JSONResponse({"detail": "Origin not allowed"}, status_code=403)
            if request.headers.get("sec-fetch-site") == "cross-site" and not (companion and extension_origin_valid):
                return JSONResponse({"detail": "Cross-site request rejected"}, status_code=403)
            length = request.headers.get("content-length", "0")
            if not length.isdigit() or int(length) > 160_000:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
            content = bytearray()
            async for chunk in request.stream():
                content.extend(chunk)
                if len(content) > 160_000:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
            request._body = bytes(content)
        response = await call_next(request)
        if companion and extension_origin_valid:
            response.headers["Access-Control-Allow-Origin"] = extension_origin
            response.headers["Vary"] = "Origin"
        response.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Content-Security-Policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://api.pwnedpasswords.com; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'", "Cache-Control": "no-store"})
        if settings.secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def throttle(bucket, limit=12):
        timestamp = time.time()
        with store.connect(write=True) as c:
            c.execute("DELETE FROM attempts WHERE started<?", (timestamp - 900,))
            row = c.execute("SELECT * FROM attempts WHERE bucket=?", (bucket,)).fetchone()
            if row and row["count"] >= limit:
                raise HTTPException(429, "Too many attempts. Wait 15 minutes.")
            c.execute("INSERT INTO attempts VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET count=count+1", (bucket, timestamp))

    def auth(request: Request):
        token = digest(request.cookies.get("sentinel_session", ""))
        with store.connect() as c:
            row = c.execute("SELECT s.*,u.email,m.role FROM sessions s JOIN users u ON u.id=s.user JOIN members m ON m.workspace=s.workspace AND m.user=s.user WHERE s.token=? AND s.expires>? AND s.pending=0", (token, time.time())).fetchone()
        if not row:
            raise HTTPException(401, "Sign in required")
        if request.method != "GET" and not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), row["csrf"]):
            raise HTTPException(403, "CSRF token required")
        return dict(row)

    def writable(session):
        must(session["role"] in {"owner", "analyst", "reviewer"}, "Read-only role", 403)

    def owner(session):
        must(session["role"] == "owner", "Workspace owner required", 403)

    def reviewer(session):
        must(session["role"] in {"owner", "reviewer"}, "Reviewer role required", 403)

    def issue(c, response, user, workspace, pending=False):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        duration = 300 if pending else 12 * 3600
        c.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        c.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)", (digest(token), user, workspace, csrf, time.time() + duration, int(pending)))
        response.set_cookie("sentinel_session", token, httponly=True, secure=settings.secure, samesite="strict", max_age=duration, path="/")
        return {"csrf": csrf, "mfa_required": pending}

    def new_workspace(c, user, name, demo=False):
        identifier = uid()
        c.execute("INSERT INTO workspaces VALUES(?,?,?)", (identifier, name, int(demo)))
        c.execute("INSERT INTO members VALUES(?,?,?)", (identifier, user, "owner"))
        Store.event(c, identifier, user, "workspace.created", identifier)
        return identifier

    @app.get("/api/status")
    def status():
        with store.connect() as c:
            setup_required = not c.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return {"service": "SentinelOps", "setup_required": setup_required}

    @app.post("/api/setup")
    def setup(body: Credentials, request: Request, response: Response):
        throttle("setup:" + request.client.host)
        with store.connect() as c:
            must(not c.execute("SELECT 1 FROM users LIMIT 1").fetchone(), "Setup already completed", 409)
        must(bootstrap_path.exists() and hmac.compare_digest(body.token.get_secret_value(), bootstrap_path.read_text().strip()), "Invalid bootstrap token", 403)
        try:
            password_policy(body.password.get_secret_value())
        except ValueError as e:
            raise HTTPException(422, str(e))
        encoded = hash_password(body.password.get_secret_value())
        with store.connect(write=True) as c:
            must(not c.execute("SELECT 1 FROM users LIMIT 1").fetchone(), "Setup already completed", 409)
            user = uid()
            c.execute("INSERT INTO users(id,email,password) VALUES(?,?,?)", (user, body.email, encoded))
            workspace = new_workspace(c, user, body.workspace_name)
            result = issue(c, response, user, workspace)
        bootstrap_path.unlink(missing_ok=True)
        return result

    @app.post("/api/login")
    def login(body: Credentials, request: Request, response: Response):
        throttle("login-ip:" + request.client.host, 40)
        throttle("login-user:" + digest(body.email))
        must(len(body.password.get_secret_value()) <= 128, "Invalid credentials", 401)
        with store.connect(write=True) as c:
            user = c.execute("SELECT * FROM users WHERE email=?", (body.email,)).fetchone()
            valid = verify_password(body.password.get_secret_value(), user["password"] if user else dummy_password)
            must(user and valid, "Invalid credentials", 401)
            membership = c.execute("SELECT m.workspace FROM members m JOIN workspaces w ON w.id=m.workspace WHERE m.user=? AND w.demo=0 ORDER BY m.rowid LIMIT 1", (user["id"],)).fetchone()
            must(membership, "Invalid credentials", 401)
            workspace = membership[0]
            c.execute("DELETE FROM sessions WHERE token=?", (digest(request.cookies.get("sentinel_session", "")),))
            result = issue(c, response, user["id"], workspace, bool(user["mfa"]))
            if not user["mfa"]:
                Store.event(c, workspace, user["id"], "auth.signed_in", user["id"])
            return result

    @app.post("/api/login/factor")
    def login_factor(body: Code, request: Request, response: Response):
        throttle("factor:" + request.client.host)
        with store.connect(write=True) as c:
            session = c.execute("SELECT * FROM sessions WHERE token=? AND pending=1 AND expires>?", (digest(request.cookies.get("sentinel_session", "")), time.time())).fetchone()
            must(session and hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), session["csrf"]), "Challenge expired", 403)
            user = c.execute("SELECT * FROM users WHERE id=?", (session["user"],)).fetchone()
            must(user and c.execute('SELECT 1 FROM members m JOIN workspaces w ON w.id=m.workspace WHERE m.user=? AND m.workspace=? AND w.demo=0',(session['user'],session['workspace'])).fetchone(), "Challenge expired or workspace access unavailable", 403)
            must(consume_factor(c, user, body.code, cipher), "Invalid or already used code", 401)
            c.execute("DELETE FROM sessions WHERE token=?", (session["token"],))
            result = issue(c, response, user["id"], session["workspace"])
            Store.event(c, session["workspace"], user["id"], "auth.signed_in_mfa", user["id"])
            return result

    @app.post("/api/logout")
    def logout(response: Response, session=Depends(auth)):
        with store.connect(write=True) as c:
            c.execute("DELETE FROM sessions WHERE token=?", (session["token"],))
            c.execute('DELETE FROM passkey_ceremonies WHERE account=?',(session['user'],))
        response.delete_cookie("sentinel_session", path="/")
        response.delete_cookie('sentinel_passkey_binding',path='/api/passkeys')
        return {"ok": True}

    from .passkey_routes import install_routes as install_passkey_routes
    install_passkey_routes(app,store,settings,cipher,auth,issue,throttle)

    def vault_metadata(row):
        result = {key:row[key] for key in ("id","name","purpose","color","lock_seconds","browser_enabled","browser_save","browser_fill","archived","is_default","revision","created_at","updated_at")}
        result.update(origins=json.loads(row["origins"]), initialized=row["payload"] != 'null')
        return result

    def find_vault(c, user, identifier=""):
        row = c.execute("SELECT * FROM vault_spaces WHERE user=? AND " + ("id=?" if identifier else "is_default=1"), (user,identifier) if identifier else (user,)).fetchone()
        if identifier:
            must(row, "Vault not found")
        return row

    def create_vault_record(c, user, properties, make_default=False):
        at, identifier = now(), uid()
        if make_default:
            for prior in c.execute('SELECT id FROM vault_spaces WHERE user=? AND is_default=1',(user,)).fetchall():
                Store.event(c,'personal:'+user,user,'vault.default_changed',prior['id'])
            c.execute('UPDATE vault_spaces SET is_default=0 WHERE user=?', (user,))
        c.execute('INSERT INTO vault_spaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (identifier,user,properties.name,properties.purpose,properties.color,properties.lock_seconds,int(properties.browser_enabled),int(properties.browser_save),int(properties.browser_fill),canonical(properties.origins),int(properties.archived),int(make_default),0,'null',at,at))
        Store.event(c,'personal:'+user,user,'vault.created',identifier)
        return find_vault(c,user,identifier)

    @app.get('/api/vaults')
    def list_vaults(session=Depends(auth)):
        with store.connect() as c:
            return {"vaults":[vault_metadata(row) for row in c.execute('SELECT * FROM vault_spaces WHERE user=? ORDER BY is_default DESC,created_at', (session['user'],))]}

    @app.post('/api/vaults')
    def create_vault_space(body: VaultProperties, session=Depends(auth)):
        must(not body.archived, 'Create an active vault first', 422)
        with store.connect(write=True) as c:
            count = c.execute('SELECT count(*) FROM vault_spaces WHERE user=?', (session['user'],)).fetchone()[0]
            must(count < 20, 'This installation supports up to 20 vaults per account', 409)
            row = create_vault_record(c,session['user'],body,body.is_default or not count)
            return vault_metadata(row)

    @app.post('/api/vaults/{identifier}')
    def update_vault_space(identifier: str, body: VaultProperties, session=Depends(auth)):
        with store.connect(write=True) as c:
            row = find_vault(c,session['user'],identifier)
            must(not body.archived or not row['is_default'], 'Choose another default before archiving this vault', 409)
            must(not body.is_default or not body.archived, 'An archived vault cannot be the default', 422)
            if body.is_default:
                for prior in c.execute('SELECT id FROM vault_spaces WHERE user=? AND is_default=1 AND id!=?',(session['user'],identifier)).fetchall():
                    Store.event(c,'personal:'+session['user'],session['user'],'vault.default_changed',prior['id'])
                c.execute('UPDATE vault_spaces SET is_default=0 WHERE user=?', (session['user'],))
            # Revocation is immediate when browser access is disabled/archived.
            if body.archived or not body.browser_enabled:
                record_connection_revocations(c,c.execute("SELECT * FROM companions WHERE kind='personal' AND user=? AND vault_id=?",(session['user'],identifier)).fetchall(),session['user'])
                c.execute("DELETE FROM companions WHERE kind='personal' AND user=? AND vault_id=?", (session['user'],identifier))
            c.execute('UPDATE vault_spaces SET name=?,purpose=?,color=?,lock_seconds=?,browser_enabled=?,browser_save=?,browser_fill=?,origins=?,archived=?,is_default=?,updated_at=? WHERE id=? AND user=?', (body.name,body.purpose,body.color,body.lock_seconds,int(body.browser_enabled),int(body.browser_save),int(body.browser_fill),canonical(body.origins),int(body.archived),int(body.is_default or row['is_default']),now(),identifier,session['user']))
            Store.event(c,'personal:'+session['user'],session['user'],'vault.properties_updated',identifier)
            if bool(row['archived'])!=body.archived:
                Store.event(c,'personal:'+session['user'],session['user'],'vault.archived' if body.archived else 'vault.restored',identifier)
            return vault_metadata(find_vault(c,session['user'],identifier))

    def read_vault(user, identifier="", browser=False):
        with store.connect() as c:
            row = find_vault(c,user,identifier)
            if row and browser:
                must(not row['archived'] and row['browser_enabled'], 'Browser access to this vault is disabled', 403)
        return {"revision": row['revision'], "envelope": json.loads(row['payload']), "vault":vault_metadata(row)} if row else {"revision":0,"envelope":None}

    def write_vault(user, body, identifier="", browser=False):
        with store.connect(write=True) as c:
            row = find_vault(c,user,identifier)
            if not row:
                row = create_vault_record(c,user,VaultProperties(name='Personal'),True)
            must(not row['archived'], 'Restore this archived vault before editing', 409)
            if body.envelope.version == 2:
                must(body.envelope.context == row['id'], 'Encrypted vault context does not match the selected vault', 422)
            previous = json.loads(row['payload'])
            must(not previous or previous.get('version') != 2 or body.envelope.version == 2, 'This vault requires the current protected envelope format', 409)
            if browser:
                must(row['browser_enabled'] and row['browser_save'], 'Saving from the browser is disabled for this vault', 403)
            must(body.revision == row['revision'], "Vault changed in another tab or companion. Lock, reload and unlock before editing again.", 409)
            c.execute('UPDATE vault_spaces SET revision=?,payload=?,updated_at=? WHERE id=? AND user=?', (body.revision+1,canonical(body.envelope.model_dump()),now(),row['id'],user))
            Store.event(c,'personal:'+user,user,'vault.browser_saved' if browser else 'vault.saved' if previous else 'vault.initialized',row['id'])
            if previous and body.envelope.version == 2 and (previous.get('version') != 2 or previous.get('wrapped_key') != body.envelope.wrapped_key):
                record_connection_revocations(c,c.execute("SELECT * FROM companions WHERE kind='personal' AND user=? AND vault_id=?",(user,row['id'])).fetchall(),user)
                c.execute("DELETE FROM companions WHERE kind='personal' AND user=? AND vault_id=?", (user,row['id']))
                Store.event(c,'personal:'+user,user,'vault.protection_changed',row['id'])
        return {"revision":body.revision+1, "vault_id":row['id']}

    @app.get("/api/vault")
    def vault_get(vault_id: str = "", session=Depends(auth)):
        return read_vault(session["user"], vault_id)

    @app.post("/api/vault")
    def vault_save(body: VaultWrite, vault_id: str = "", session=Depends(auth)):
        throttle("vault-write:" + session["user"], 120)
        return write_vault(session["user"], body, vault_id)

    def companion_auth(request):
        authorization = request.headers.get("authorization", "")
        must(authorization.startswith("Bearer "), "Companion token required", 401)
        with store.connect() as c:
            row = c.execute("SELECT * FROM companions WHERE token=? AND expires>?", (digest(authorization[7:]), time.time())).fetchone()
        must(row and row['vault_id'], "Companion token expired or revoked", 401)
        return dict(row)

    @app.get("/api/companion/vault")
    def companion_read(request: Request):
        connection = companion_auth(request)
        if connection['kind']=='shared':
            return shared_companions['read'](connection)
        return read_vault(connection['user'],connection['vault_id'],True)

    @app.post("/api/companion/vault")
    def companion_save(body: CompanionWrite, request: Request):
        connection = companion_auth(request)
        throttle("vault-write:" + connection['user'], 120)
        if connection['kind']=='shared':
            must(isinstance(body.envelope,TeamPayload),'A shared vault envelope is required',422)
            return shared_companions['write'](connection,body.revision,body.envelope)
        must(isinstance(body.envelope,(VaultEnvelope,VaultEnvelopeV2)),'A personal vault envelope is required',422)
        return write_vault(connection['user'], body, connection['vault_id'], True)

    @app.get("/api/companions")
    def companions(session=Depends(auth)):
        with store.connect() as c:
            rows = [dict(r) for r in c.execute("SELECT label,expires FROM companions WHERE user=? AND expires>?", (session["user"], time.time()))]
        return {"connections": rows}

    @app.post("/api/device-connections")
    def connect_device(body: DeviceConnection, session=Depends(auth)):
        from .device_checks import validate_target
        writable(session)
        throttle("device-connect:" + session["user"], 10)
        try:
            targets = list(dict.fromkeys(validate_target(value) for value in body.targets))
        except ValueError as error:
            raise HTTPException(422, str(error))
        with store.connect(write=True) as c:
            user = c.execute("SELECT * FROM users WHERE id=?", (session["user"],)).fetchone()
            must(verify_password(body.password.get_secret_value(), user["password"]), "Current sign-in password required", 401)
            if user["mfa"]:
                must(consume_factor(c, user, body.code, cipher), "Unused authenticator/recovery code required", 401)
            must(c.execute("SELECT count(*) FROM devices WHERE workspace=? AND expires>?", (session["workspace"], time.time())).fetchone()[0] < 20, "Device connection limit reached", 409)
            identifier, token = uid(), secrets.token_urlsafe(40)
            c.execute("INSERT INTO devices(id,token,workspace,user,label,targets,expires,seen,allow_posture) VALUES(?,?,?,?,?,?,?,NULL,?)", (identifier, digest(token), session["workspace"], session["user"], body.label, canonical(targets), time.time()+30*86400,int(body.allow_posture)))
            Store.event(c, session["workspace"], session["user"], "device.connected", identifier)
        return {"id": identifier, "label":body.label, "server":settings.origin, "token":token, "allowed_targets":targets, "allow_posture":body.allow_posture, "expires_days":30}

    @app.post("/api/device-connections/{identifier}/revoke")
    def disconnect_device(identifier: str, session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            device = must(c.execute("SELECT * FROM devices WHERE id=? AND workspace=?", (identifier, session["workspace"])).fetchone())
            must(device["user"] == session["user"] or session["role"] == "owner", "Only the connection owner or workspace owner can revoke it", 403)
            c.execute("DELETE FROM devices WHERE id=?", (identifier,))
            for operation in Store.all(c, session["workspace"], "operations"):
                if operation.get("device_id") == identifier and operation["status"] in {"queued", "running"}:
                    operation.update(status="interrupted", error="Device connection revoked.", finished_at=now())
                    Store.put(c, session["workspace"], "operations", operation)
            Store.event(c, session["workspace"], session["user"], "device.revoked", identifier)
        return {"ok":True}

    def device_auth(request, c):
        authorization = request.headers.get("authorization", "")
        must(authorization.startswith("Bearer "), "Device token required", 401)
        device = must(c.execute("SELECT d.* FROM devices d JOIN members m ON d.user=m.user AND d.workspace=m.workspace WHERE d.token=? AND d.expires>? AND m.role!='viewer'", (digest(authorization[7:]), time.time())).fetchone(), "Device connection expired or revoked", 401)
        return dict(device)

    @app.post("/api/device-agent/poll")
    def device_poll(body: DevicePoll,request: Request):
        with store.connect(write=True) as c:
            device = device_auth(request, c)
            c.execute("UPDATE devices SET seen=?,protocol_version=?,posture_enabled=? WHERE id=?", (time.time(),body.version,int(body.version==2 and body.posture_enabled), device["id"]))
            operations = Store.all(c, device["workspace"], "operations")
            for operation in operations:
                if operation.get("device_id") == device["id"] and operation["status"] == "running":
                    if operation.get("lease_expires", 0) <= time.time():
                        operation.update(status="interrupted", error="Device response timed out. Retry explicitly.", finished_at=now())
                        Store.put(c, device["workspace"], "operations", operation)
                    else:
                        return {"operation":None}
            operation = next((o for o in reversed(operations) if o.get("device_id") == device["id"] and o["status"] == "queued"), None)
            if not operation:
                return {"operation":None}
            if operation['action']=='posture' and (body.version<2 or not body.posture_enabled):
                operation.update(status='failed',error='The connected client did not enable host posture tools. Run agent 0.7+ with --allow-posture and an opted-in connection, then retry explicitly.',finished_at=now())
                Store.put(c,device['workspace'],'operations',operation)
                return {'operation':None,'notice':'Posture tool unavailable; nothing was collected.'}
            member = c.execute("SELECT role FROM members WHERE workspace=? AND user=?", (device["workspace"], operation["created_by"])).fetchone()
            if not member or member["role"] == "viewer" or operation["target"] not in json.loads(device["targets"]) or operation['action']=='posture' and not device['allow_posture']:
                operation.update(status="failed", error="Requested device scope is no longer authorized.")
                Store.put(c, device["workspace"], "operations", operation)
                return {"operation":None}
            lease = secrets.token_urlsafe(32)
            operation.update(status="running", lease=digest(lease), lease_expires=time.time()+180, steps=[{"agent":"Scope verifier", "status":"complete"}, {"agent":"Connected device operator", "status":"running"}])
            Store.put(c, device["workspace"], "operations", operation)
            return {"operation":{"id":operation["id"], 'action':operation['action'], "target":operation["target"], "ports":operation["ports"], "lease":lease}}

    @app.post("/api/device-agent/result")
    def device_result(body: DeviceResult, request: Request):
        from types import SimpleNamespace
        with store.connect(write=True) as c:
            device = device_auth(request, c)
            operation = must(Store.get(c, device["workspace"], "operations", body.operation_id))
            must(operation.get("device_id") == device["id"] and operation["status"] == "running" and operation.get("lease_expires", 0) > time.time() and hmac.compare_digest(operation.get("lease", ""), digest(body.lease.get_secret_value())), "Device job lease expired or invalid", 409)
            member = c.execute("SELECT role FROM members WHERE workspace=? AND user=?", (device["workspace"], operation["created_by"])).fetchone()
            must(member and member["role"] != "viewer", "Requester permission was removed", 403)
            observations = [o.model_dump() for o in body.observations]
            must(len(observations) == len(operation["ports"]) and {(o["host"], o["port"]) for o in observations} == {(operation["target"], p) for p in operation["ports"]}, "Report must match the authorized target and ports exactly", 422)
            if operation['action']=='posture':
                from .posture import assessment
                must(device['allow_posture'] and device['protocol_version']>=2 and device['posture_enabled'] and operation['target'] in {'127.0.0.1','::1'} and body.posture is not None,'A consented operator-local posture report is required',422)
                result=assessment(body.posture,paired=True)
            else:
                must(body.posture is None,'Posture was not authorized for this TCP job',422)
                items = [scanner.finding("PORT001", evidence=f"Connected device reported a TCP listener on {o['host']}:{o['port']}. Service identity, exploitability and public exposure are unverified.", confidence="low", host=o["host"], port=o["port"]) for o in observations if o["status"] == "open"]
                result = dict(findings=items, observations=observations, error="Some device ports could not be assessed." if any(o["status"] == "unassessed" for o in observations) else None, limits="Reported by a paired device, not independent attestation. One authorized IP and selected TCP ports. Open ports are not proven vulnerabilities. No commands or system changes.")
            asset = must(Store.get(c, device["workspace"], "assets", operation["asset_id"]))
            scan = persist_scan(c, device["workspace"], operation["created_by"], asset, SimpleNamespace(kind='posture' if operation['action']=='posture' else 'device', label="Connected device " + device["id"]), result)
            operation.update(status=scan["status"], scan_id=scan["id"], finding_ids=scan["finding_ids"], finished_at=now(), limits=scan["limits"])
            operation.pop("lease", None)
            operation["steps"][1]["status"] = scan["status"]
            operation["steps"].append({"agent":"Evidence recorder", "status":"complete"})
            if operation.get("ai_triage") and scan["finding_ids"]:
                job = dict(id=uid(), mode="remediation", finding_ids=scan["finding_ids"][:20], status="queued", created_by=operation["created_by"], created_at=now(), steps=[], permissions={"create_tasks":True,"create_investigation":False})
                Store.put(c, device["workspace"], "jobs", job)
                operation["agent_job"] = job["id"]
            Store.put(c, device["workspace"], "operations", operation)
            Store.event(c, device["workspace"], operation["created_by"], "operation.completed", operation["id"])
        if operation.get("agent_job"):
            executor.submit(agents.run_job, store, device["workspace"], operation["agent_job"], settings.groq_key, settings.model, app.state.agent_transport)
        return {"ok":True, "status":operation["status"]}

    @app.post("/api/companions")
    def pair(body: PairRequest, session=Depends(auth)):
        throttle("pair:" + session["user"])
        with store.connect(write=True) as c:
            user = c.execute("SELECT * FROM users WHERE id=?", (session["user"],)).fetchone()
            must(verify_password(body.password.get_secret_value(), user["password"]), "Current password required", 401)
            if user["mfa"]:
                must(consume_factor(c, user, body.code, cipher), "Unused authenticator or recovery code required", 401)
            token = secrets.token_urlsafe(40)
            if body.kind=='shared':
                vault=shared_companions['metadata'](c,session,body.vault_id)
            else:
                vault = find_vault(c,user['id'],body.vault_id)
                if not vault:
                    vault = create_vault_record(c,user['id'],VaultProperties(name='Personal'),True)
                must(not vault['archived'] and vault['browser_enabled'], 'Enable browser access on an active vault before connecting it', 409)
            c.execute("INSERT INTO companions(token,user,label,expires,vault_id,kind,workspace) VALUES(?,?,?,?,?,?,?)", (digest(token), user["id"], body.label, time.time() + 30 * 86400, vault['id'],body.kind,session['workspace'] if body.kind=='shared' else None))
            Store.event(c, session["workspace"], session["user"], "companion.token_created", "encrypted-vault-only")
            Store.event(c,session['workspace'] if body.kind=='shared' else 'personal:'+session['user'],session['user'],('team_vault.' if body.kind=='shared' else 'vault.')+'companion_connected',vault['id'])
        return {"token": token, "origin": settings.origin, "expires_days": 30, "vault_id":vault['id'], "vault_name":vault['name'], 'kind':body.kind, "scope": "One selected shared vault and your encrypted sharing identity; no access to other vaults, workspace endpoints or plaintext." if body.kind=='shared' else "One selected encrypted vault only; no access to other vaults, workspace endpoints or plaintext."}

    @app.post("/api/companions/revoke")
    def revoke_companions(session=Depends(auth)):
        with store.connect(write=True) as c:
            record_connection_revocations(c,c.execute('SELECT * FROM companions WHERE user=?',(session['user'],)).fetchall(),session['user'])
            c.execute("DELETE FROM companions WHERE user=?", (session["user"],))
            Store.event(c, session["workspace"], session["user"], "companion.revoked_all", session["user"])
        return {"ok": True}

    @app.get("/api/me")
    def me(session=Depends(auth)):
        with store.connect() as c:
            spaces = [dict(r) for r in c.execute("SELECT w.*,m.role FROM workspaces w JOIN members m ON m.workspace=w.id WHERE m.user=? AND w.demo=0", (session["user"],))]
            user = c.execute("SELECT mfa,recovery FROM users WHERE id=?", (session["user"],)).fetchone()
        return {"id": session["user"], "email": session["email"], "role": session["role"], "workspace": session["workspace"], "csrf": session["csrf"], "workspaces": spaces, "mfa_enabled": bool(user["mfa"]), "recovery_remaining": len(json.loads(user["recovery"]))}

    @app.post("/api/workspaces")
    def create_workspace(body: Workspace, session=Depends(auth)):
        with store.connect(write=True) as c:
            identifier = new_workspace(c, session["user"], body.name)
        return {"id": identifier}

    @app.post("/api/workspaces/{identifier}/switch")
    def switch(identifier: str, response: Response, session=Depends(auth)):
        with store.connect(write=True) as c:
            must(c.execute("SELECT 1 FROM members m JOIN workspaces w ON m.workspace=w.id WHERE m.user=? AND m.workspace=? AND w.demo=0", (session["user"], identifier)).fetchone(), "Workspace not found")
            c.execute("DELETE FROM sessions WHERE token=?", (session["token"],))
            return issue(c, response, session["user"], identifier)

    @app.post("/api/invites")
    def invite(body: Invite, session=Depends(auth)):
        owner(session)
        email = body.email.lower().strip()
        must("@" in email and " " not in email, "Invalid email", 422)
        token = secrets.token_urlsafe(32)
        with store.connect(write=True) as c:
            c.execute("INSERT INTO invites VALUES(?,?,?,?,?)", (digest(token), session["workspace"], email, body.role, time.time() + 86400))
            Store.event(c, session["workspace"], session["user"], "member.invited", body.role)
        return {"token": token, "expires_in_hours": 24, "note": "Share privately. No email was sent."}

    @app.post("/api/join")
    def join(body: Credentials, request: Request, response: Response):
        throttle("join:" + request.client.host)
        must(len(body.password.get_secret_value()) <= 128, "Invalid credentials", 401)
        with store.connect(write=True) as c:
            invitation = c.execute("SELECT * FROM invites WHERE token=? AND email=? AND expires>?", (digest(body.token.get_secret_value()), body.email, time.time())).fetchone()
            must(invitation, "Invalid or expired invitation", 403)
            user = c.execute("SELECT * FROM users WHERE email=?", (body.email,)).fetchone()
            if user:
                must(verify_password(body.password.get_secret_value(), user["password"]), "Invalid credentials", 401)
                if user["mfa"]:
                    must(consume_factor(c, user, body.code, cipher), "Authenticator or recovery code required", 401)
                user_id = user["id"]
            else:
                try:
                    password_policy(body.password.get_secret_value())
                except ValueError as e:
                    raise HTTPException(422, str(e))
                user_id = uid()
                c.execute("INSERT INTO users(id,email,password) VALUES(?,?,?)", (user_id, body.email, hash_password(body.password.get_secret_value())))
            must(not c.execute("SELECT 1 FROM members WHERE workspace=? AND user=?", (invitation["workspace"], user_id)).fetchone(), "Already a member", 409)
            c.execute("INSERT INTO members VALUES(?,?,?)", (invitation["workspace"], user_id, invitation["role"]))
            c.execute("DELETE FROM invites WHERE token=?", (invitation["token"],))
            Store.event(c, invitation["workspace"], user_id, "member.joined", user_id)
            return issue(c, response, user_id, invitation["workspace"])

    @app.post("/api/mfa/setup")
    def mfa_setup(body: Reauth, session=Depends(auth)):
        throttle("mfa:" + session["user"])
        with store.connect(write=True) as c:
            user = c.execute("SELECT * FROM users WHERE id=?", (session["user"],)).fetchone()
            must(verify_password(body.password.get_secret_value(), user["password"]), "Invalid password", 401)
            must(not user["mfa"], "MFA already enabled", 409)
            secret = base64.b32encode(secrets.token_bytes(20)).decode()
            draft = cipher.encrypt(canonical({"secret": secret, "expires": time.time() + 600}).encode()).decode()
            c.execute("UPDATE users SET mfa_draft=? WHERE id=?", (draft, user["id"]))
        return {"secret": secret, "uri": f"otpauth://totp/SentinelOps:{quote(session['email'])}?secret={secret}&issuer=SentinelOps&algorithm=SHA1&digits=6&period=30"}

    @app.post("/api/mfa/enable")
    def mfa_enable(body: Code, response: Response, session=Depends(auth)):
        throttle("mfa:" + session["user"])
        with store.connect(write=True) as c:
            user = c.execute("SELECT * FROM users WHERE id=?", (session["user"],)).fetchone()
            must(user["mfa_draft"] and not user["mfa"], "Start setup first", 409)
            draft = json.loads(cipher.decrypt(user["mfa_draft"].encode()))
            step = check_totp(draft["secret"], body.code)
            must(draft["expires"] > time.time() and step is not None, "Expired setup or invalid code", 401)
            codes = [secrets.token_hex(10) for _ in range(8)]
            c.execute("UPDATE users SET mfa=?,mfa_draft=NULL,mfa_step=?,recovery=? WHERE id=?", (cipher.encrypt(draft["secret"].encode()).decode(), step, json.dumps([digest(v) for v in codes]), user["id"]))
            c.execute("DELETE FROM sessions WHERE user=?", (user["id"],))
            result = issue(c, response, user["id"], session["workspace"])
            Store.event(c, session["workspace"], user["id"], "auth.mfa_enabled", user["id"])
        return {**result, "recovery_codes": codes}

    @app.post("/api/mfa/disable")
    def mfa_disable(body: Reauth, response: Response, session=Depends(auth)):
        throttle("mfa:" + session["user"])
        with store.connect(write=True) as c:
            user = c.execute("SELECT * FROM users WHERE id=?", (session["user"],)).fetchone()
            must(verify_password(body.password.get_secret_value(), user["password"]) and consume_factor(c, user, body.code, cipher), "Password and unused factor required", 401)
            c.execute("UPDATE users SET mfa=NULL,mfa_draft=NULL,mfa_step=-1,recovery='[]' WHERE id=?", (user["id"],))
            c.execute("DELETE FROM sessions WHERE user=?", (user["id"],))
            result = issue(c, response, user["id"], session["workspace"])
            Store.event(c, session["workspace"], user["id"], "auth.mfa_disabled", user["id"])
        return result

    @app.post("/api/members/{identifier}/offboard")
    def offboard_member(identifier: str,body: Reauth,session=Depends(auth)):
        owner(session);throttle('offboard:'+session['user'],8)
        with store.connect(write=True) as c:
            member=must(c.execute('SELECT m.*,u.email FROM members m JOIN users u ON u.id=m.user WHERE m.workspace=? AND m.user=?',(session['workspace'],identifier)).fetchone(),'Member not found')
            must(member['role']!='owner' and identifier!=session['user'],'Workspace owners cannot be removed here',409)
            must(not c.execute('SELECT 1 FROM team_vaults WHERE workspace=? AND owner=?',(session['workspace'],identifier)).fetchone(),'This member owns a shared vault. Transfer its ownership to an accepted teammate before offboarding.',409)
            user=c.execute('SELECT * FROM users WHERE id=?',(session['user'],)).fetchone()
            must(verify_password(body.password.get_secret_value(),user['password']),'Current sign-in password required',401)
            if user['mfa']:
                must(consume_factor(c,user,body.code,cipher),'Unused authenticator or recovery code required',401)
            affected=[r['id'] for r in c.execute('SELECT v.id FROM team_vaults v JOIN team_grants g ON v.id=g.vault WHERE v.workspace=? AND g.user=?',(session['workspace'],identifier))]
            for vault in affected:
                c.execute('DELETE FROM team_grants WHERE vault=? AND user=?',(vault,identifier))
                c.execute('UPDATE team_vaults SET rotation_required=1 WHERE id=?',(vault,))
                invalidate_ownership(c,session['workspace'],vault,session['user'],'member_offboarded')
                Store.event(c,session['workspace'],session['user'],'team_vault.access_revoked',vault+':'+identifier)
            devices=[r['id'] for r in c.execute('SELECT id FROM devices WHERE workspace=? AND user=?',(session['workspace'],identifier))]
            c.execute('DELETE FROM devices WHERE workspace=? AND user=?',(session['workspace'],identifier))
            for kind in ('operations','jobs'):
                for job in Store.all(c,session['workspace'],kind):
                    if job['status'] in {'queued','running'} and (job['created_by']==identifier or job.get('device_id') in devices):
                        job.update(status='cancelled',finished_at=now(),error='Workspace access removed.')
                        Store.put(c,session['workspace'],kind,job)
            c.execute('DELETE FROM sessions WHERE workspace=? AND user=?',(session['workspace'],identifier))
            record_connection_revocations(c,c.execute("SELECT * FROM companions WHERE kind='shared' AND workspace=? AND user=?",(session['workspace'],identifier)).fetchall(),session['user'])
            c.execute("DELETE FROM companions WHERE kind='shared' AND workspace=? AND user=?",(session['workspace'],identifier))
            record_action_cancellations(c,c.execute("SELECT id,workspace,user FROM credential_actions WHERE kind='shared' AND workspace=? AND user=? AND status NOT IN ('complete','cancelled','expired')",(session['workspace'],identifier)).fetchall(),session['user'])
            c.execute("UPDATE credential_actions SET status='cancelled',lease_hash=NULL,lease_connection=NULL,lease_expires=NULL WHERE kind='shared' AND workspace=? AND user=? AND status NOT IN ('complete','cancelled','expired')",(session['workspace'],identifier))
            c.execute('DELETE FROM invites WHERE workspace=? AND email=?',(session['workspace'],member['email']))
            c.execute('DELETE FROM members WHERE workspace=? AND user=?',(session['workspace'],identifier))
            for watch in Store.all(c,session['workspace'],'watches'):
                if watch['created_by']==identifier and (watch['enabled'] or watch.get('active_run')):
                    app.state.watch_service.stop_watch(c,session['workspace'],watch,'Watch owner offboarded; explicit owner takeover required.','cancelled')
                    app.state.watch_service.notification(c,session['workspace'],watch,None,'paused')
            # Preserve account sign-in and personal vault access after its last team is removed.
            if not c.execute('SELECT 1 FROM members m JOIN workspaces w ON w.id=m.workspace WHERE m.user=? AND w.demo=0',(identifier,)).fetchone():
                new_workspace(c,identifier,'Personal security workspace')
            Store.event(c,session['workspace'],session['user'],'member.offboarded',identifier)
        return {'ok':True,'vaults_requiring_rotation':affected,'note':'Shared access and device grants removed. Rotate affected vault keys and known website passwords. Cached copies cannot be erased.'}

    @app.get("/api/workspace")
    def workspace_data(session=Depends(auth)):
        workspace = session["workspace"]
        with store.connect() as c:
            result = {kind: Store.all(c, workspace, kind) for kind in ("assets", "scans", "findings", "tasks", "investigations", "jobs", "operations")}
            result["members"] = [dict(r) for r in c.execute("SELECT u.id,u.email,m.role FROM members m JOIN users u ON m.user=u.id WHERE m.workspace=?", (workspace,))]
            result["audit"] = Store.audit(c, workspace)
            from .ownership import incoming as incoming_ownership
            result['ownership_requests']=incoming_ownership(c,workspace,session['user']) if session['role']!='viewer' else []
        result["integrations"] = {"groq_configured": bool(settings.groq_key), "groq_model": settings.model, "scan_hosts": sorted(settings.scan_hosts), "osv": "Live API, exact pins only", "password_privacy": "Browser-local strength; optional HIBP hash-prefix lookup"}
        result["integrations"]["local_device_agent"] = not settings.secure and settings.host in {"localhost", "127.0.0.1"}
        with store.connect() as c:
            vault_count = c.execute("SELECT count(*) FROM vault_spaces WHERE user=? AND payload!='null'", (session["user"],)).fetchone()[0]
            result["connections"] = {"vault_created": bool(vault_count), "vault_count":vault_count, "browser_tokens": c.execute("SELECT count(*) FROM companions WHERE user=? AND expires>?", (session["user"], time.time())).fetchone()[0]}
            result["devices"] = [{"id":r["id"], "label":r["label"], "targets":json.loads(r["targets"]), "seen":r["seen"], "expires":r["expires"], 'allow_posture':bool(r['allow_posture']),'protocol_version':r['protocol_version'],'posture_enabled':bool(r['posture_enabled'])} for r in c.execute("SELECT id,label,targets,seen,expires,allow_posture,protocol_version,posture_enabled FROM devices WHERE workspace=? AND expires>?", (workspace,time.time()))]
        for operation in result["operations"]:
            operation.pop("lease", None)
            operation.pop("lease_expires", None)
        return result

    @app.post("/api/assets")
    def create_asset(body: Asset, session=Depends(auth)):
        writable(session)
        must(body.authorized, "Confirm authorization for this asset", 422)
        if body.hostname:
            try:
                body.hostname = scanner.validate_host(body.hostname)
            except ValueError as e:
                raise HTTPException(422, str(e))
        value = dict(id=uid(), **body.model_dump(), created_at=now())
        with store.connect(write=True) as c:
            Store.put(c, session["workspace"], "assets", value)
            Store.event(c, session["workspace"], session["user"], "asset.created", value["id"])
        return value

    def persist_scan(c, workspace, actor, asset, body, result):
        identifier, at = uid(), now()
        items = result.pop("findings")
        existing = Store.all(c, workspace, "findings")
        fingerprints = {v["fingerprint"]: v for v in existing}
        ids = []
        scope = dict(asset_id=asset["id"], kind=body.kind, label=body.label)
        for previous in existing:
            if all(previous.get(k) == v for k, v in scope.items()):
                previous["observed_in_latest"] = False
                Store.put(c, workspace, "findings", previous)
        for item in items:
            if item.get('rule')=='DEP001' and item.get('advisory_ids'):
                # A provider can report a different ID for the same alias group.
                # Retain the existing finding identity and its linked work, but
                # never join a different asset, scope, version or package.
                names=set(item['advisory_ids'])
                candidates=[v for v in existing if v['id'] not in ids and v.get('rule')=='DEP001'
                            and all(v.get(k)==value for k,value in scope.items()) and v.get('package')==item.get('package')
                            and names.intersection(v.get('advisory_ids') or [v.get('advisory')])]
                if candidates:
                    anchor=min(candidates,key=lambda v:(v.get('advisory')!=item['advisory'],v['first_seen'],v['id']))
                    item['advisory']=anchor['advisory']
                    item['reference']='https://osv.dev/vulnerability/'+anchor['advisory']
            fingerprint = digest(canonical({**scope, "rule": item["rule"], "line": item["line"], "advisory": item.get("advisory"), "package": item.get("package"), "port": item.get("port"), "host": item.get("host"), **({'posture_check':item['posture_check']} if 'posture_check' in item else {})}))
            previous = fingerprints.get(fingerprint)
            value = {**item, **scope, "fingerprint": fingerprint, "id": previous["id"] if previous else uid(), "first_seen": previous["first_seen"] if previous else at, "last_seen": at, "scan_id": identifier, "status": "open", "observed_in_latest": True}
            Store.put(c, workspace, "findings", value)
            ids.append(value["id"])
            if previous and previous["status"] == "resolved":
                Store.event(c, workspace, actor, "finding.reopened", value["id"])
                for task in Store.all(c, workspace, "tasks"):
                    if task["finding_id"] == value["id"] and task["status"] == "resolved":
                        task.update(status="open", reopened_at=at)
                        Store.put(c, workspace, "tasks", task)
                for case in Store.all(c, workspace, "investigations"):
                    if value["id"] in case["finding_ids"] and case["status"] == "closed":
                        case.update(status="investigating")
                        case["notes"].append(dict(text="A linked finding was observed again. Investigation reopened automatically.", by=actor, at=at))
                        Store.put(c, workspace, "investigations", case)
        value = dict(id=identifier, **scope, at=at, created_by=actor, finding_ids=ids, status="partial" if result.get("error") or result.get("skipped") else "complete", **result)
        Store.put(c, workspace, "scans", value)
        Store.event(c, workspace, actor, "scan.completed" if value["status"] == "complete" else "scan.partial", identifier)
        return value

    def run_operation(workspace, actor, identifier, body):
        from types import SimpleNamespace
        from .device_checks import assess
        try:
            with store.connect(write=True) as c:
                operation = Store.get(c, workspace, "operations", identifier)
                if not operation or operation["status"] != "queued":
                    return
                member = c.execute("SELECT role FROM members WHERE workspace=? AND user=?", (workspace, actor)).fetchone()
                if not member or member["role"] == "viewer":
                    raise ValueError("Device/check permission was removed before execution.")
                operation.update(status="running", steps=[{"agent": "Scope verifier", "status": "complete"}, {"agent": "Device operator" if body.action == "device" else "Assessment operator", "status": "running"}])
                Store.put(c, workspace, "operations", operation)
            if body.action == "device":
                result = assess(body.target, body.ports)
            elif body.action=='posture':
                from companion.device_agent import collect_posture
                from .posture import assessment
                result=assessment(collect_posture())
            elif body.action == "website":
                result = scanner.scan_web(body.target, settings.scan_hosts)
            elif body.action == "python":
                result = scanner.scan_python(body.content.get_secret_value())
            elif body.action == "dependencies":
                result = scanner.scan_dependencies(body.content.get_secret_value(), body.format)
            else:
                result = scanner.scan_email(body.content.get_secret_value())
            with store.connect(write=True) as c:
                member = c.execute("SELECT role FROM members WHERE workspace=? AND user=?", (workspace, actor)).fetchone()
                if not member or member["role"] == "viewer":
                    raise ValueError("Permission removed before recording results.")
                current_operation = Store.get(c, workspace, "operations", identifier)
                if not current_operation or current_operation["status"] != "running":
                    return
                asset = Store.get(c, workspace, "assets", operation["asset_id"])
                scan_body = SimpleNamespace(kind=body.action, label="Host posture operator" if body.action=="posture" else "Device operator" if body.action == "device" else "Website operator" if body.action == "website" else "Submitted " + body.action)
                scan = persist_scan(c, workspace, actor, asset, scan_body, result)
                operation.update(status=scan["status"], scan_id=scan["id"], finding_ids=scan["finding_ids"], finished_at=now(), limits=scan["limits"])
                operation["steps"][1]["status"] = scan["status"]
                operation["steps"].append({"agent": "Evidence recorder", "status": "complete"})
                if body.ai_triage and scan["finding_ids"]:
                    job = dict(id=uid(), mode="remediation", finding_ids=scan["finding_ids"][:20], status="queued", created_by=actor, created_at=now(), steps=[], permissions={"create_tasks": True, "create_investigation": False})
                    Store.put(c, workspace, "jobs", job)
                    Store.event(c, workspace, actor, "agent.queued", job["id"])
                    operation["agent_job"] = job["id"]
                Store.put(c, workspace, "operations", operation)
                Store.event(c, workspace, actor, "operation.completed", identifier)
            if operation.get("agent_job"):
                agents.run_job(store, workspace, operation["agent_job"], settings.groq_key, settings.model, app.state.agent_transport)
        except Exception as error:
            with store.connect(write=True) as c:
                operation = Store.get(c, workspace, "operations", identifier)
                if operation and operation["status"] in {"queued", "running"}:
                    operation.update(status="failed", error=str(error) if isinstance(error, ValueError) else "Assessment could not finish. Check connectivity and retry explicitly.", finished_at=now())
                    for step in operation.get("steps", []):
                        if step["status"] == "running":
                            step["status"] = "failed"
                    Store.put(c, workspace, "operations", operation)
                    Store.event(c, workspace, actor, "operation.failed", identifier)

    app.state.run_operation = run_operation

    @app.post("/api/operations")
    def create_operation(body: OperationRequest, session=Depends(auth)):
        from .device_checks import validate_target
        writable(session)
        must(body.authorized, "Confirm authorization for the selected target", 422)
        throttle("operation:" + session["workspace"], 30)
        must(not body.ai_triage or settings.groq_key, "Connect Groq before requesting AI triage", 503)
        try:
            if body.action in {'device','posture'}:
                must(body.device_id != "local" or (not settings.secure and settings.host in {"localhost", "127.0.0.1"}), "This installation has no local device operator. A hosted server cannot assess your computer without an installed device connection.", 409)
                body.target = validate_target(body.target)
                if body.action=='posture':
                    must(body.target in {'127.0.0.1','::1'},'Host posture checks assess only the selected agent computer; use a loopback target, not another LAN device',422)
                must(all(1 <= p <= 65535 for p in body.ports), "Ports must be 1–65535", 422)
            elif body.action == "website":
                body.target = scanner.validate_host(body.target)
                must(body.target in settings.scan_hosts, "Website must be in the server operator's SCAN_HOSTS allowlist", 422)
            else:
                must(bool(body.content.get_secret_value().strip()), "Attach or paste content to assess", 422)
                must(len(body.content.get_secret_value()) <= (15000 if body.action == "email" else 100000), "Submitted content exceeds the assessment limit", 422)
                body.target = "Submitted " + body.action
        except ValueError as error:
            raise HTTPException(422, str(error))
        with store.connect(write=True) as c:
            must(not any(o["status"] in {"queued", "running"} for o in Store.all(c, session["workspace"], "operations")), "An assessment is already active", 409)
            if body.action in {'device','posture'} and body.device_id != "local":
                device = must(c.execute("SELECT targets,allow_posture FROM devices WHERE id=? AND workspace=? AND expires>?", (body.device_id,session["workspace"],time.time())).fetchone(), "Device connection unavailable")
                must(body.target in json.loads(device["targets"]), "Target is outside this device connection's allowed scope", 422)
                must(body.action!='posture' or device['allow_posture'],'This device connection did not opt in to read-only posture collection. Create a consented connection and run the new agent with --allow-posture.',409)
            kind = "device" if body.action in {'device','posture'} else "website" if body.action == "website" else "mailbox" if body.action == "email" else "application"
            asset = next((a for a in Store.all(c, session["workspace"], "assets") if a.get("operator_target") == body.target and a["kind"] == kind and a.get("device_id", "local") == body.device_id), None)
            if not asset:
                asset = dict(id=uid(), name=body.target, kind=kind, owner=session["email"], environment="development" if kind == "device" else "production", criticality="medium", hostname=body.target if kind == "website" else "", authorized=True, operator_target=body.target, device_id=body.device_id, created_at=now())
                Store.put(c, session["workspace"], "assets", asset)
                Store.event(c, session["workspace"], session["user"], "asset.connected", asset["id"])
            operation = dict(id=uid(), action=body.action, target=body.target, asset_id=asset["id"], status="queued", created_by=session["user"], created_at=now(), steps=[], device_id=body.device_id, ports=sorted(set(body.ports)) if body.action == "device" else [], ai_triage=body.ai_triage)
            Store.put(c, session["workspace"], "operations", operation)
            Store.event(c, session["workspace"], session["user"], "operation.queued", operation["id"])
        if body.action not in {'device','posture'} or body.device_id == "local":
            executor.submit(run_operation, session["workspace"], session["user"], operation["id"], body)
        return operation

    @app.post("/api/operations/{identifier}/cancel")
    def cancel_operation(identifier: str, session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            operation = must(Store.get(c, session["workspace"], "operations", identifier))
            must(operation["created_by"] == session["user"] or session["role"] == "owner", "Only the requester or workspace owner can cancel this operation", 403)
            must(operation["status"] in {"queued", "running"}, "Operation is already finished", 409)
            operation.update(status="cancelled", finished_at=now(), error="Cancelled. A device check already in progress may finish locally, but further results are rejected.")
            operation.pop("lease", None)
            Store.put(c, session["workspace"], "operations", operation)
            Store.event(c, session["workspace"], session["user"], "operation.cancelled", identifier)
        return {"ok":True}

    @app.post("/api/scans")
    def create_scan(body: Scan, session=Depends(auth)):
        writable(session)
        throttle("scan:" + session["workspace"], 30)
        must(body.authorized, "Confirm you may assess this content", 422)
        with store.connect() as c:
            asset = must(Store.get(c, session["workspace"], "assets", body.asset_id))
        content = body.content.get_secret_value()
        must(body.kind == "website" or bool(content.strip()), "Submit content to assess", 422)
        try:
            if body.kind == "python":
                result = scanner.scan_python(content)
            elif body.kind == "dependencies":
                result = scanner.scan_dependencies(content, body.format)
            elif body.kind == "email":
                must(len(content) <= 15000, "Email must be at most 15,000 characters", 422)
                result = scanner.scan_email(content)
            else:
                result = scanner.scan_web(asset["hostname"], settings.scan_hosts)
        except ValueError as e:
            raise HTTPException(422, str(e))
        except (OSError, http.client.HTTPException):
            raise HTTPException(502, "Website assessment failed. No result was recorded; check DNS, TLS and availability.")
        with store.connect(write=True) as c:
            return persist_scan(c, session["workspace"], session["user"], asset, body, result)

    @app.get("/api/downloads/{kind}")
    def companion_download(kind: str, session=Depends(auth)):
        if kind == "device-agent":
            return FileResponse(ROOT / "companion" / "device_agent.py", filename="sentinelops_device_agent.py", media_type="text/x-python")
        if kind == "browser-companion":
            path = ROOT / "companion" / "extension" / "sentinelops-companion.zip"
            must(path.exists(), "Build the companion package before downloading", 503)
            return FileResponse(path, filename="sentinelops-companion.zip", media_type="application/zip")
        raise HTTPException(404, "Download not found")

    @app.post("/api/device-reports")
    def import_device(body: DeviceImport, session=Depends(auth)):
        writable(session)
        must(body.authorized, "Confirm you may assess this device", 422)
        from datetime import datetime
        from types import SimpleNamespace
        from companion.device_agent import PORTS
        try:
            generated = datetime.fromisoformat(body.report.generated_at)
            must(generated.tzinfo is not None, "Report time must include a timezone", 422)
            age = time.time() - generated.timestamp()
            must(-300 <= age <= 7 * 86400, "Import a report from the last seven days; verify the device clock", 422)
        except ValueError:
            raise HTTPException(422, "Invalid report timestamp")
        observations = body.report.observations
        must(len({(p.host, p.port) for p in observations}) == len(observations), "Duplicate observations", 422)
        must(all(p.port in PORTS for p in observations), "Report contains ports outside the companion's fixed scope", 422)
        missing = len(observations) != len(PORTS) * 2
        items = [scanner.finding("PORT001", evidence=f"A user-supplied local report observed a TCP listener on {p.host}:{p.port}. Service identity and external reachability are unknown.", confidence="low", port=p.port, host=p.host) for p in observations if p.status == "open"]
        result = dict(findings=items, generated_at=body.report.generated_at, observations=[p.model_dump() for p in observations], error="Some loopback checks were missing or unassessed." if missing or any(p.status == "unassessed" for p in observations) else None, limits="Imported self-report, not remote attestation. Fixed TCP ports on the reporting machine's IPv4/IPv6 loopback only. No UDP, full port range, process attribution, exploit testing or proof of public exposure. An open port is an observation, not a proven vulnerability.")
        with store.connect(write=True) as c:
            asset = must(Store.get(c, session["workspace"], "assets", body.asset_id))
            return persist_scan(c, session["workspace"], session["user"], asset, SimpleNamespace(kind="device", label="Local device report"), result)

    @app.post("/api/tasks")
    def create_task(body: Task, session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            finding = must(Store.get(c, session["workspace"], "findings", body.finding_id))
            must(finding["status"] == "open", "Finding already resolved", 409)
            member = c.execute("SELECT role FROM members WHERE workspace=? AND user=?", (session["workspace"], body.assignee)).fetchone()
            must(member and member["role"] != "viewer", "Assignee must be an active contributor", 422)
            must(not any(t["finding_id"] == body.finding_id and t["status"] != "resolved" for t in Store.all(c, session["workspace"], "tasks")), "An active task already exists", 409)
            if body.due:
                from datetime import date
                try:
                    date.fromisoformat(body.due)
                except ValueError:
                    raise HTTPException(422, "Due date must be YYYY-MM-DD")
            value = dict(id=uid(), **body.model_dump(), title=finding["title"], status="open", created_by=session["user"], created_at=now(), history=[])
            Store.put(c, session["workspace"], "tasks", value)
            Store.event(c, session["workspace"], session["user"], "task.created", value["id"])
        return value

    @app.post("/api/tasks/{identifier}")
    def update_task(identifier: str, body: TaskUpdate, session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            task = must(Store.get(c, session["workspace"], "tasks", identifier))
            if body.action in {"start", "submit"}:
                must(session["user"] == task["assignee"], "Only the assigned contributor can submit work", 403)
                must(task["status"] in {"open", "in_progress"}, "Task is not editable in this state", 409)
                if body.action == "submit":
                    must(len(body.evidence) >= 15, "Describe the change and verification evidence (15+ characters)", 422)
                    task.update(status="pending_review", submitted_by=session["user"], evidence=body.evidence, submitted_scan=Store.get(c, session["workspace"], "findings", task["finding_id"])["scan_id"])
                else:
                    task["status"] = "in_progress"
            else:
                reviewer(session)
                must(task["status"] == "pending_review", "Task is not awaiting review", 409)
                must(task["submitted_by"] != session["user"], "An independent reviewer must decide", 403)
                must(len(body.evidence) >= 15, "Add review evidence or a reason (15+ characters)", 422)
                current = must(Store.get(c, session["workspace"], "findings", task["finding_id"]))
                must(body.action != "approve" or current["scan_id"] == task["submitted_scan"], "Finding changed after submission; reject and resubmit against current evidence", 409)
                task.update(status="resolved" if body.action == "approve" else "in_progress", reviewed_by=session["user"], review=body.evidence)
                if body.action == "approve":
                    current.update(status="resolved", resolved_at=now())
                    Store.put(c, session["workspace"], "findings", current)
            task["history"].append(dict(action=body.action, by=session["user"], at=now(), note=body.evidence))
            Store.put(c, session["workspace"], "tasks", task)
            Store.event(c, session["workspace"], session["user"], "task." + body.action, identifier)
        return task

    @app.post("/api/investigations")
    def create_investigation(body: Investigation, session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            for identifier in body.finding_ids:
                must(Store.get(c, session["workspace"], "findings", identifier))
            value = dict(id=uid(), title=body.title, finding_ids=list(dict.fromkeys(body.finding_ids)), status="open", created_by=session["user"], created_at=now(), notes=[dict(text=body.note, by=session["user"], at=now())] if body.note else [])
            Store.put(c, session["workspace"], "investigations", value)
            Store.event(c, session["workspace"], session["user"], "investigation.created", value["id"])
        return value

    @app.post("/api/investigations/{identifier}")
    def update_investigation(identifier: str, body: InvestigationUpdate, session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            value = must(Store.get(c, session["workspace"], "investigations", identifier))
            if body.status == "closed":
                reviewer(session)
                must(all(Store.get(c, session["workspace"], "findings", f)["status"] == "resolved" for f in value["finding_ids"]), "Resolve linked findings through reviewed tasks first", 409)
            value.update(status=body.status)
            value["notes"].append(dict(text=body.note, by=session["user"], at=now()))
            Store.put(c, session["workspace"], "investigations", value)
            Store.event(c, session["workspace"], session["user"], "investigation.updated", identifier)
        return value

    @app.post("/api/agents")
    def create_agent(body: AgentRequest, session=Depends(auth)):
        writable(session)
        must(settings.groq_key, "Configure GROQ_API_KEY in .env before running agents", 503)
        throttle("agent:" + session["workspace"], 10)
        with store.connect(write=True) as c:
            must(not any(j["status"] in {"queued", "running"} for j in Store.all(c, session["workspace"], "jobs")), "An agent run is already active", 409)
            for identifier in body.finding_ids:
                finding = must(Store.get(c, session["workspace"], "findings", identifier))
                must(finding["status"] == "open", "Select open findings for an agent workflow", 409)
            value = dict(id=uid(), mode=body.mode, finding_ids=list(dict.fromkeys(body.finding_ids)), status="queued", created_by=session["user"], created_at=now(), steps=[], permissions={"create_tasks": body.create_tasks, "create_investigation": body.create_investigation})
            Store.put(c, session["workspace"], "jobs", value)
            Store.event(c, session["workspace"], session["user"], "agent.queued", value["id"])
        executor.submit(agents.run_job, store, session["workspace"], value["id"], settings.groq_key, settings.model, app.state.agent_transport)
        return value

    @app.post("/api/agents/{identifier}/progress")
    def agent_progress(identifier: str, session=Depends(auth)):
        writable(session)
        with store.connect(write=True) as c:
            job = must(Store.get(c, session["workspace"], "jobs", identifier))
            must(job["status"] == "complete", "Only completed workflows can check progress", 409)
            result = agents.check_progress(c, session["workspace"], job)
            Store.event(c, session["workspace"], session["user"], "agent.progress_checked", identifier)
            return result

    @app.get("/api/report")
    def report(session=Depends(auth)):
        with store.connect() as c:
            workspace = dict(c.execute("SELECT * FROM workspaces WHERE id=?", (session["workspace"],)).fetchone())
            data = {kind: Store.all(c, session["workspace"], kind) for kind in ("assets", "scans", "findings", "tasks", "investigations")}
            audit = Store.audit(c, session["workspace"])
        value = dict(product="SentinelOps", version="0.12.0", generated_at=now(), workspace=workspace, **data, audit=audit, limitations="User-provided observations and reviewed decisions, not a security certification. Hash links reveal some edits relative to a retained external head; a database administrator can rewrite the whole chain. No independent signing authority.")
        value["content_sha256"] = hashlib.sha256(canonical(value).encode()).hexdigest()
        return JSONResponse(value, headers={"Content-Disposition": 'attachment; filename="sentinelops-evidence.json"'})

    from .sharing import register as register_sharing
    shared_companions=register_sharing(app,store,auth,writable,throttle)
    from .credential_actions import register as register_credential_actions
    register_credential_actions(app,store,auth,companion_auth,throttle)
    from .vault_activity import register as register_vault_activity
    register_vault_activity(app,store,auth,throttle)
    from .watches import register as register_watches
    app.state.watch_service=register_watches(app,store,auth,writable,throttle,persist_scan)

    dist = ROOT / "frontend" / "dist"
    app.mount("/assets", StaticFiles(directory=dist / "assets", check_dir=False), name="assets")

    @app.get("/")
    def index():
        if not (dist / "index.html").exists():
            return JSONResponse({"detail": "Build frontend: cd frontend; npm ci; npm run build"}, status_code=503)
        return FileResponse(dist / "index.html")

    return app
