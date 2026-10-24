# Companion packaging and verification

Build with the committed frontend lockfile using the existing README commands:
`npm ci`, then `npm run build:companion` from `frontend/`, followed by
`.venv\Scripts\python.exe companion/package_extension.py` from the repository root.
The packager prints JSON with the version, archive SHA-256, per-file hashes and
uncompressed size. It replaces `companion/extension/sentinelops-companion.zip`
only after validation and a successful temporary ZIP write.

Required root entry points are manifest.json, content.js, background.js,
popup.html and vault-frame.html. Only direct assets/*.js, *.css and *.wasm are
accepted in addition. Unexpected files (including .env, JSON configuration and
source maps), symlinks/junctions, stale/non-object manifests and oversized builds
are rejected. A small heuristic also rejects recognizable Groq key/private-key
markers without printing the matching value. It cannot detect every secret or
establish that bundled code is safe. Review sources and permissions separately.

ZIP order, timestamps, file permissions and compression settings are fixed.
Two clean 0.13.0 builds on the same pinned local toolchain produced the same ZIP:
`e445d3e9ba40e0b84374a054191c53ecb64123133ac9d06a983c626da74c3c18`.
The artifact record is companion-release-0.13.0.json. This is local reproducibility
evidence, not a claim of cross-platform/toolchain equivalence or a signed release.
Compare a downloaded file with PowerShell's `Get-FileHash -Algorithm SHA256`.
A checksum identifies bytes; it does not establish a trusted publisher by itself.

The package tests cover deterministic metadata, unexpected/credential-like files,
missing/stale manifests, symlink rejection and interrupted-write preservation.
The native symlink test is skipped if Windows denies unprivileged creation; a
separate simulated-path test always exercises rejection. Extension-store
submission, publisher signing, independent review and installed 0.13.0 acceptance
remain open. Rebuilding the ZIP does not reload an already-installed extension.
