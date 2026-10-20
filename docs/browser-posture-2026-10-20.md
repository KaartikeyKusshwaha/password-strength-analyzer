# Actual Edge Windows posture acceptance — 2026-10-20

Launched the existing local read-only Windows protection operator through Control center, with ownership authorization selected and optional AI planning disabled.

The actual operation completed with Partial coverage and zero findings. The UI reported the domain, private, and public firewall profiles enabled, and Microsoft Defender antivirus/realtime status enabled. System-drive BitLocker was unassessed because permission was denied. No elevation, protection changes, or recovery-key access was attempted. The UI correctly retained the partial result and explained its coverage limits instead of treating zero findings as proof of security.

An Edge session/tab replacement occurred before the first launch attempt; that tab handle failed before action. Reconnected to the newly inventoried tab and launched one assessment there. Final result was read from that actual operation, not inferred from tests.

Companion follow-up: user's new popup screenshot shows the expired/revoked-connection error instead of Illegal invocation. This demonstrates progression past the receiver bug but does not establish successful pairing or decryption. Popup still selected Personal vault. Prepared the dashboard's connection form for Browser acceptance; no new token issued by the agent. User must complete that scoped pairing or select an existing valid Browser acceptance connection. Screenshot: data/browser-acceptance-0.12.0/reconnect-browser-acceptance.png.
