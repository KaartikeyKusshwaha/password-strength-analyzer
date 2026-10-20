"""Bounded OSV alias lookup and package-scoped grouping, without an LLM."""
import json
import re
import time

import httpx


ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}')


def enrich(items, transport=None):
    """Preserve matches if detail coverage is unavailable; never infer severity."""
    identifiers = sorted({item['advisory'] for item in items})
    details = {}
    attempted = 0
    deadline = time.monotonic() + 20
    with httpx.Client(timeout=3, transport=transport, follow_redirects=False) as client:
        for identifier in identifiers[:20]:
            if time.monotonic() >= deadline:
                break
            attempted += 1
            try:
                with client.stream('GET', 'https://api.osv.dev/v1/vulns/' + identifier) as response:
                    response.raise_for_status()
                    raw = bytearray()
                    for chunk in response.iter_bytes(chunk_size=16384):
                        raw.extend(chunk)
                        if len(raw) > 256000 or time.monotonic() >= deadline:
                            raise ValueError()
                value = json.loads(raw)
                if not isinstance(value, dict) or value.get('id') != identifier or value.get('withdrawn'):
                    raise ValueError()
                aliases = value.get('aliases', [])
                if not isinstance(aliases, list) or len(aliases) > 100 or any(not isinstance(a, str) or not ID.fullmatch(a) for a in aliases):
                    raise ValueError()
                details[identifier] = sorted(set([identifier, *aliases]))
            except (httpx.HTTPError, ValueError, TypeError):
                # Matching and detail coverage are separate. No fabricated aliases.
                continue
    groups = []
    for item in items:
        names = set(details.get(item['advisory'], [item['advisory']]))
        overlaps = [group for group in groups if group['package'] == item['package'] and names.intersection(group['advisory_ids'])]
        if not overlaps:
            groups.append({**item, 'advisory_ids': sorted(names), 'matched_advisories': [item['advisory']]})
            continue
        target = overlaps[0]
        for group in overlaps[1:]:
            names.update(group['advisory_ids'])
            target['matched_advisories'].extend(group['matched_advisories'])
            groups.remove(group)
        names.update(target['advisory_ids'])
        target['advisory_ids'] = sorted(names)
        target['matched_advisories'] = sorted(set([*target['matched_advisories'], item['advisory']]))
    for group in groups:
        # Prefer a matched ID, not an unqueried alias, for the primary reference.
        group['advisory'] = min(group['matched_advisories'])
        group['reference'] = 'https://osv.dev/vulnerability/' + group['advisory']
        package = group['package']
        group['evidence'] = f"OSV matches {package['ecosystem']} {package['name']}@{package['version']} to " + ', '.join(group['matched_advisories']) + '. Grouped only through returned alias relationships; reachability is not established.'
    coverage = dict(total=len(identifiers), attempted=attempted, completed=len(details), grouped_matches=len(items)-len(groups))
    coverage['status'] = 'complete' if len(details) == len(identifiers) else 'partial'
    return groups, coverage
