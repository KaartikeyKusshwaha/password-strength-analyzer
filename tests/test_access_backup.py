from backend.backups import create_backup, init_key, restore_backup
from backend.store import Store, SCHEMA_VERSION
from test_platform import system


def test_schema_ten_archive_upgrades_without_losing_prior_accounts(system, tmp_path):
    app, client, source = system
    with app.state.store.connect(write=True) as c:
        account = c.execute('SELECT id,email,password FROM users').fetchone()[:]
        c.execute('DROP TABLE client_vaults')
        c.execute('DROP TABLE clients')
        c.execute('DELETE FROM schema_migrations WHERE version>=11')
        c.execute('DROP TABLE workflow_steps')
        c.execute('DROP TABLE workflows');c.execute('DROP TABLE access_grants');c.execute('DROP TABLE credential_exposures');c.execute('DROP TABLE handoff_records')
    key, archive, destination = tmp_path/'key', tmp_path/'old.sentinelbackup', tmp_path/'restored'
    init_key(key)
    assert create_backup(source, key, archive)['schema'] == 10
    result = restore_backup(archive, key, destination)
    assert result['source_schema'] == 10 and result['schema'] == SCHEMA_VERSION
    with Store(destination/'sentinelops.db').connect() as c:
        assert c.execute('SELECT id,email,password FROM users').fetchone()[:] == account
        assert c.execute('SELECT count(*) FROM clients').fetchone()[0] == 0
