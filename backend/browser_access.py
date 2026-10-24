"""Recheck scoped bearer access inside the transaction that uses it."""
import time

from fastapi import HTTPException


def require_connection(c, connection):
    if not connection:
        raise HTTPException(401, 'Companion token expired or revoked')
    row=c.execute('SELECT * FROM companions WHERE token=? AND user=? AND expires>?',
                  (connection['token'],connection['user'],time.time())).fetchone()
    if not row or any(row[key]!=connection[key] for key in ('vault_id','kind','workspace')):
        raise HTTPException(401, 'Companion token expired or revoked')
    return row
