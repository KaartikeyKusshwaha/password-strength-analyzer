"""Bounded connection diagnostics; client reports never authorize an action."""
import json
import re
import time
from zipfile import BadZipFile, ZipFile

from .security import digest
from .store import Store

KIND = 'companion_status'
HEADER = 'X-Sentinel-Companion-Version'


def valid_version(value):
    return value if isinstance(value, str) and len(value) <= 14 and re.fullmatch(r'(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){2}', value) else None


def identifier(token_hash):
    return digest('companion-status:' + token_hash)


def packaged_version(path):
    try:
        with ZipFile(path) as archive:
            info = archive.getinfo('manifest.json')
            if info.file_size > 8192:
                return None
            return valid_version(json.loads(archive.read(info)).get('version'))
    except (OSError, BadZipFile, KeyError, ValueError, AttributeError):
        return None


def record_read(store, connection, version, timestamp=None):
    """Record only after an authorized vault read; do not record URLs or values."""
    at = time.time() if timestamp is None else timestamp
    reported = valid_version(version)
    key = identifier(connection['token'])
    scope = 'personal:' + connection['user']
    with store.connect(write=True) as c:
        c.execute("DELETE FROM entities WHERE kind=? AND json_extract(data,'$.expires')<=?", (KIND, at))
        # A token revoked while the read was completing must not revive status.
        live = c.execute('SELECT 1 FROM companions WHERE token=? AND user=? AND expires>?', (connection['token'], connection['user'], at)).fetchone()
        if not live:
            return
        previous = Store.get(c, scope, KIND, key)
        if previous and previous['version'] == reported and 0 <= at - previous['seen'] < 60:
            return
        Store.put(c, scope, KIND, {'id':key, 'version':reported, 'seen':at, 'expires':connection['expires']})


def public_status(c, connection):
    value = Store.get(c, 'personal:' + connection['user'], KIND, identifier(connection['token']))
    return {'id':identifier(connection['token']), 'label':connection['label'], 'kind':connection['kind'],
            'expires':connection['expires'], 'last_contact':value['seen'] if value else None,
            'reported_version':value['version'] if value else None}


def forget(c, connection):
    c.execute('DELETE FROM entities WHERE id=? AND workspace=? AND kind=?',
              (identifier(connection['token']), 'personal:' + connection['user'], KIND))
