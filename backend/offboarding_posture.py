"""Retain bounded, recorded helper observations at the first real removal.

No new scan, device command or external request is authorized by this module.
The snapshot and first removal share the existing workflow transaction.
"""
from datetime import datetime, timezone
import json

from .posture import Check
from .store import Store

KIND = 'offboarding_posture'
LIMITS = ('Recorded helper self-reports at the first selected vault removal; '
          'not independent device attestation, a new scan, or proof of device '
          'return, wiping, external account removal or current protection. '
          'Devices without a surviving paired connection are not discoverable.')


def capture(c, row, clock):
    """Exactly once per workflow, including when its worker resumes."""
    saved = Store.get(c, row['workspace'], KIND, row['id'])
    if saved is not None:
        return saved
    at = clock()
    devices = c.execute(
        'SELECT id,expires FROM devices WHERE workspace=? AND user=? ORDER BY id LIMIT 101',
        (row['workspace'], row['person'])).fetchall()
    observations = []
    for device in devices[:100]:
        # Only workspace-local assets explicitly bound to this paired device.
        # Scan insertion order is server-recorded, unlike the helper timestamp.
        candidates = c.execute("""
            SELECT s.data FROM entities s JOIN entities a
            ON a.id=json_extract(s.data,'$.asset_id') AND a.workspace=s.workspace
            AND a.kind='assets'
            WHERE s.workspace=? AND s.kind='scans'
            AND json_extract(s.data,'$.kind')='posture'
            AND json_extract(a.data,'$.device_id')=?
            ORDER BY s.rowid DESC LIMIT 1
        """, (row['workspace'], device['id'])).fetchall()
        scan = json.loads(candidates[0][0]) if candidates else {}
        raw = scan.get('posture') if isinstance(scan.get('posture'), dict) else {}
        checks = []
        for check in raw.get('checks', [])[:5] if isinstance(raw.get('checks'), list) else []:
            try:
                checks.append(Check.model_validate(check).model_dump())
            except (ValueError, TypeError):
                continue
        recorded = scan.get('at')
        try:
            stamp = datetime.fromisoformat(recorded)
            age = at-stamp.timestamp() if stamp.tzinfo else None
        except (ValueError, TypeError):
            age = None
        observations.append({
            'device': device['id'], 'connection_expired': device['expires'] <= at,
            'scan': scan.get('id'), 'recorded_at': recorded,
            'freshness': 'recorded_within_24h' if age is not None and 0 <= age <= 86400 else 'stale_or_unavailable',
            'platform': raw.get('platform') if raw.get('platform') in {'windows','macos','linux','other'} else 'unknown',
            'checks': checks,
        })
    value = {'id': row['id'], 'person': row['person'],
             'captured_at': datetime.fromtimestamp(at, timezone.utc).isoformat(),
             'devices': observations, 'device_limit_reached': len(devices) > 100,
             'limitations': LIMITS}
    Store.put(c, row['workspace'], KIND, value)
    Store.event(c, row['workspace'], row['created_by'], 'access_workflow.posture_recorded', row['id'])
    return value


def retained(c, row):
    return Store.get(c, row['workspace'], KIND, row['id'])
