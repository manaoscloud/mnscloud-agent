#!/usr/bin/python3
"""Converge the local MariaDB account of the SSH diagnostics schema-status and schema-plan commands
(diagnostics 4.0, 4.5).

Runs as root from scripts/install-diagnostics.sh on every Agent install/update, only on database
hosts. The account is 'mns-diagnostics'@'localhost' IDENTIFIED VIA unix_socket: only the OS account
of the same name can use it, through the local socket, and no password exists anywhere. It holds
SELECT on the fixed columns below and nothing else; any other grant found is revoked. Never prints
credentials. Exit 0 also when the host is not a database server.
"""
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

ACCOUNT_NAME = 'mns-diagnostics'
ACCOUNT = "'mns-diagnostics'@'localhost'"
DB_ENV = Path('/etc/mnscloud/db.env')
MIGRATION_ENV = Path('/etc/mnscloud/db-migration.env')
MARIADB = Path('/usr/bin/mariadb')
COLUMNS = {
    'SchemaAppliedRevision': ('SarClusterKey', 'SarDbReleaseTag', 'SarAppliedAt', 'SarStatus', 'SarDateDeleted'),
    'SchemaReconcileJob': ('SrjStage', 'SrjDbReleaseTag', 'SrjStatus', 'SrjStartedAt', 'SrjFinishedAt',
                           'SrjLastErrorCode', 'SrjDateCreated', 'SrjDateDeleted', 'SrjResultJson'),
}
COLUMN_GRANT = re.compile(r'^GRANT SELECT \((.+)\) ON `([A-Za-z0-9_]+)`\.`([A-Za-z0-9_]+)` TO `mns-diagnostics`@`localhost`$')


def private_env(path):
    """Literal KEY=value parsing of a root-only env file (never sourced)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
            raise ValueError('Unsafe env file')
        values = {}
        for line in stream.read().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, sep, value = line.removeprefix('export ').partition('=')
            value = value.strip()
            if len(value) > 1 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if sep:
                values[key.strip()] = value
        return values


def sql(statement, database, password):
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
    if password:
        env['MYSQL_PWD'] = password  # child environment only, never argv or output
    result = subprocess.run([str(MARIADB), '-uroot', '--protocol=socket', '-N', '--batch', '--raw', database,
                             '-e', statement], env=env, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError('mariadb exited with code %d' % result.returncode)
    return result.stdout


def unexpected_grants(lines, database, tables):
    """Grants of the account other than USAGE and the allowed column SELECTs."""
    extra = []
    for line in (line.strip() for line in lines if line.strip()):
        if line.startswith('GRANT USAGE ON *.* TO `mns-diagnostics`@`localhost`'):
            continue
        match = COLUMN_GRANT.match(line)
        if match and match.group(2) == database and match.group(3) in tables:
            columns = {name.strip().strip('`') for name in match.group(1).split(',')}
            if columns <= set(COLUMNS[match.group(3)]):
                continue
        extra.append(line)
    return extra


def converge(run=sql):
    if not DB_ENV.exists() or not MARIADB.exists():
        return {'status': 'NOT_A_DATABASE_HOST'}
    pwd.getpwnam(ACCOUNT_NAME)  # the OS account must exist first (manage.py)
    database = private_env(DB_ENV).get('DB_NAME', '')
    if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', database):
        raise ValueError('Invalid DB_NAME')
    password = ''
    for path in (MIGRATION_ENV, DB_ENV):
        if path.exists():
            password = private_env(path).get('DB_ROOT_PASSWORD', '') or password
            if password:
                break

    def execute(statement):
        return run(statement, database, password)

    names = ','.join("'%s'" % name for name in COLUMNS)
    tables = set(execute('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() '
                         'AND TABLE_NAME IN (%s);' % names).split())
    execute('CREATE USER IF NOT EXISTS %s IDENTIFIED VIA unix_socket;' % ACCOUNT)
    execute('ALTER USER %s IDENTIFIED VIA unix_socket;' % ACCOUNT)
    if unexpected_grants(execute('SHOW GRANTS FOR %s;' % ACCOUNT).splitlines(), database, tables):
        execute('REVOKE ALL PRIVILEGES, GRANT OPTION FROM %s;' % ACCOUNT)
    for table in sorted(tables):
        columns = ', '.join('`%s`' % column for column in COLUMNS[table])
        execute('GRANT SELECT (%s) ON `%s`.`%s` TO %s;' % (columns, database, table, ACCOUNT))
    extra = unexpected_grants(execute('SHOW GRANTS FOR %s;' % ACCOUNT).splitlines(), database, tables)
    if extra:
        raise RuntimeError('Diagnostics account still holds unexpected grants')
    return {'status': 'CONVERGED', 'tables': sorted(tables)}


def main():
    if os.geteuid() != 0:
        print(json.dumps({'status': 'SKIPPED_NOT_ROOT'}))
        return 1
    try:
        print(json.dumps(converge()))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        # Never echo SQL output or credentials; the type is enough to triage.
        print(json.dumps({'status': 'FAILED', 'error': type(error).__name__}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
