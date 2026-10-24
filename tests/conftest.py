"""Keep default test fixtures disconnected from any developer cloud database.

backend.app loads the root .env during collection. An explicit blank value
prevents dotenv from importing a real DATABASE_URL before fixtures can run.
PostgreSQL integration tests use their own loopback-only opt-in configuration.
Tests of environment selection can override this value with monkeypatch.
"""
import os

os.environ['DATABASE_URL']=''
