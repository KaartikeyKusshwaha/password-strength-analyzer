"""Live enrollment policy shared by browser sessions and administrative workers."""
from fastapi import HTTPException


def administrative(c, user):
    return bool(c.execute("""SELECT 1 FROM members WHERE user=? AND role='owner'
        UNION ALL SELECT 1 FROM team_grants g JOIN team_vaults v ON v.id=g.vault
        JOIN members m ON m.workspace=v.workspace AND m.user=g.user
        WHERE g.user=? AND g.accepted=1 AND g.role IN ('owner','admin') LIMIT 1""",(user,user)).fetchone())


def enrollment_required(c, user, store):
    if not getattr(store,'admin_mfa_required',True) or not administrative(c,user):return False
    account=c.execute('SELECT mfa FROM users WHERE id=?',(user,)).fetchone()
    return not account or not account['mfa']


def enforce(c,user,store):
    if enrollment_required(c,user,store):
        raise HTTPException(428,'Administrator MFA enrollment required. Sign in to SentinelOps and set up an authenticator; personal vaults remain available.')
