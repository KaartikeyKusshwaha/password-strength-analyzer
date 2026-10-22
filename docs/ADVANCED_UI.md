# Agency control room and legacy tools

The normal website navigation is Clients & Access, Workflows, Vaults,
Connections and Settings. Client map and workflow history retain their existing
owner authorization. Routine offboarding still starts and is approved in the
extension. Workflows displays the existing history and evidence component;
the client map no longer duplicates it.

Legacy control center, inventory, scans, combined reviews, findings, tasks,
investigations, agent logs, watches and raw evidence are available only in the
explicit Advanced interface. Set `ADVANCED_UI=true` in the backend environment
and restart the service to expose the entry. Its default is disabled. The
workspace response advertises this flag; `/advanced` returns 404 when disabled.
When enabled, navigation uses `/advanced#page=scans` and equivalent known pages.
Normal control room pages use `/#page=workflows` and other known primary pages.
Unknown pages fall back to the vault or the advanced overview. Back/forward and
reload restore the corresponding route.

This is a presentation flag, not an authorization boundary. Existing API role,
scope, approval and origin checks still apply. The flag does not disable scanning
engines or extension operations. Legacy components and their tests remain in the
repository. This change does not archive historical phishing records or complete
the separate removal of phishing paths.

Verification: 371 frontend tests passed across 81 files; 22 platform API tests
passed, including flag defaults, disabled/enabled route behavior and a real scan
while legacy UI is disabled. The web production build passed. These checks used
isolated disposable artifacts, subsequently moved to the user's cleanup folder.
No installed extension or Oracle deployment was replaced. Browser acceptance
remains deferred at the user's request.
