"""Isolated loopback application for browser acceptance; never a cloud target."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
folder = Path(os.environ['SENTINELOPS_E2E_DATA']).resolve()
temporary_root = Path(tempfile.gettempdir()).resolve()
if folder.parent != temporary_root or not folder.name.startswith('sentinelops-browser-') or folder.exists():
    raise SystemExit('Browser acceptance requires a fresh dedicated temporary directory.')
folder.mkdir()
# Explicit values prevent dotenv from selecting the developer's cloud database,
# server key, model provider or scanner targets when this is run locally.
for name in ('DATABASE_URL', 'APP_ENCRYPTION_KEY', 'GROQ_API_KEY', 'SCAN_HOSTS', 'BOOTSTRAP_TOKEN'):
    os.environ[name] = ''
from backend.app import Settings, create_app
import uvicorn

app = create_app(Settings(data_dir=folder, origin='http://127.0.0.1:18222',
                          database_url='', groq_key='', scan_hosts=[], admin_mfa_required=True))
uvicorn.run(app, host='127.0.0.1', port=18221, access_log=False)
