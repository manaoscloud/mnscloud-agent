#!/usr/bin/python3
"""Administrator-run installer/update/rollback; never invoked by diagnostics."""
import argparse
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

USER = 'mns-diagnostics'
HOME = Path('/var/lib/mns-diagnostics')
SHELL = Path('/usr/local/sbin/mns-diagnostics')
COLLECTOR = Path('/usr/local/lib/mns-diagnostics/collector.py')
SUDOERS = Path('/etc/sudoers.d/mns-diagnostics')
BACKUPS = Path('/var/backups/mns-diagnostics')
TARGETS = (SHELL, COLLECTOR, SUDOERS)
OPERATIONS = ('config', 'config-check', 'logs', 'logs-text', 'journal', 'container-logs', 'versions', 'connectivity', 'asterisk-odbc',
              'artifacts', 'health', 'agent', 'host', 'network', 'timers', 'edge', 'access-summary', 'log-usage',
              'voip-summary', 'schema-status')


def call(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def safe_parents(path):
    for parent in reversed(path.parents):
        if parent.exists():
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError('Unsafe parent directory: ' + str(parent))
    if path.is_symlink():
        raise RuntimeError('Refusing symlink: ' + str(path))


def atomic_write(path, content, mode):
    safe_parents(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.mns-diagnostics-')
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(content)
            os.fchmod(output.fileno(), mode)
            os.fchown(output.fileno(), 0, 0)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def backup():
    safe_parents(BACKUPS / 'placeholder')
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BACKUPS, 0o700)
    folder = Path(tempfile.mkdtemp(prefix=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-'), dir=BACKUPS))
    manifest = []
    for i, target in enumerate(TARGETS):
        safe_parents(target)
        if target.exists():
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError('Unsafe installed file: ' + str(target))
            data = target.read_bytes()
            (folder / str(i)).write_bytes(data)
            manifest.append({'mode': stat.S_IMODE(info.st_mode), 'sha256': hashlib.sha256(data).hexdigest()})
        else:
            manifest.append(None)
    (folder / 'manifest.json').write_text(json.dumps(manifest))
    return folder


def restore(folder):
    if folder.parent != BACKUPS or folder.is_symlink():
        raise RuntimeError('Rollback must name a local diagnostic backup directory.')
    safe_parents(folder / 'manifest.json')
    manifest = json.loads((folder / 'manifest.json').read_text())
    if len(manifest) != len(TARGETS):
        raise RuntimeError('Invalid backup manifest.')
    staged = []
    for i, item in enumerate(manifest):
        if item is None:
            staged.append(None)
        else:
            data = (folder / str(i)).read_bytes()
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise RuntimeError('Backup checksum mismatch.')
            staged.append(data)
    # Remove/restore privilege rule first, then restore executable definitions.
    for i in (2, 1, 0):
        if staged[i] is None:
            TARGETS[i].unlink(missing_ok=True)
        else:
            atomic_write(TARGETS[i], staged[i], manifest[i]['mode'])


def validate_account():
    account = pwd.getpwnam(USER)
    if account.pw_uid == 0 or account.pw_dir != str(HOME) or account.pw_shell != str(SHELL):
        raise RuntimeError('Existing account does not match the diagnostic contract.')
    if any(USER in group.gr_mem and group.gr_gid != account.pw_gid for group in grp.getgrall()):
        raise RuntimeError('Unexpected supplementary groups.')
    for path in (HOME, HOME / '.ssh', HOME / '.ssh/authorized_keys'):
        safe_parents(path)
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Diagnostic authorization is not root-controlled.')
    lines = (HOME / '.ssh/authorized_keys').read_text().splitlines()
    prefix = f'restrict,command="{SHELL}" ssh-ed25519 '
    if not any(line.startswith(prefix) for line in lines):
        raise RuntimeError('Restricted authorization key missing.')
    if any(line.strip() and not line.startswith('#') and not line.startswith(prefix) for line in lines):
        raise RuntimeError('Unexpected authorization options; manual review required.')


def main():
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--install', metavar='PUBLIC_KEY_FILE', type=Path)
    actions.add_argument('--update', action='store_true')
    actions.add_argument('--rollback', metavar='BACKUP_DIRECTORY', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run as root on the intended server.')
    os.umask(0o077)
    os.environ.clear()
    os.environ.update(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C')
    for program in ('sudo', 'visudo', 'runuser', 'useradd', 'ssh-keygen'):
        if not shutil.which(program):
            raise RuntimeError('Missing prerequisite: ' + program + '; install through the approved host provisioning process.')
    if args.rollback:
        restore(args.rollback.absolute())
        print('Rollback completed. Repeat local and remote diagnostics tests.')
        return
    source = Path(__file__).resolve().parent
    dispatcher = (source / 'dispatcher.sh').read_bytes()
    collector = (source / 'collector.py').read_bytes()
    compile(collector, 'collector.py', 'exec')
    call(['/bin/sh', '-n'], input=dispatcher)
    commands = ', '.join('/usr/bin/python3 -I ' + str(COLLECTOR) + ' ' + op for op in OPERATIONS)
    rule = (f'Defaults:{USER} env_reset, !setenv\n'
            f'{USER} ALL=(root) NOPASSWD: NOSETENV: {commands}\n').encode()
    with tempfile.NamedTemporaryFile() as staged:
        staged.write(rule)
        staged.flush()
        call(['visudo', '-cf', staged.name], stdout=subprocess.DEVNULL)
    public_key = None
    if args.install:
        try:
            pwd.getpwnam(USER)
        except KeyError:
            pass
        else:
            raise RuntimeError('User already exists; use --update.')
        if HOME.exists() or HOME.is_symlink() or any(p.exists() or p.is_symlink() for p in TARGETS):
            raise RuntimeError('Existing files require review before installation.')
        public_key = args.install.read_text().strip()
        if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]*)?', public_key):
            raise RuntimeError('Provide a plain Ed25519 public key.')
        call(['ssh-keygen', '-lf', str(args.install)], stdout=subprocess.DEVNULL)
    else:
        validate_account()
    saved = backup()
    print('Backup directory: ' + str(saved), flush=True)
    try:
        atomic_write(COLLECTOR, collector, 0o755)
        atomic_write(SUDOERS, rule, 0o440)
        call(['visudo', '-c'], stdout=subprocess.DEVNULL)
        atomic_write(SHELL, dispatcher, 0o755)
        if public_key is not None:
            call(['useradd', '--system', '--user-group', '--no-create-home',
                  '--home-dir', str(HOME), '--shell', str(SHELL), USER])
            for directory in (HOME, HOME / '.ssh'):
                directory.mkdir(mode=0o755)
                os.chmod(directory, 0o755)
            atomic_write(HOME / '.ssh/authorized_keys',
                         (f'restrict,command="{SHELL}" {public_key}\n').encode(), 0o644)
        validate_account()
        call(['runuser', '-u', USER, '--', 'env', 'SSH_ORIGINAL_COMMAND=identity', str(SHELL)])
        call(['runuser', '-u', USER, '--', 'env', 'SSH_ORIGINAL_COMMAND=help', str(SHELL)])
        for operation in OPERATIONS:
            # Exercise privilege delegation without reading network/config/log data.
            if operation in ('versions', 'host'):
                call(['runuser', '-u', USER, '--', 'env', 'SSH_ORIGINAL_COMMAND=' + operation, str(SHELL)],
                     stdout=subprocess.DEVNULL, timeout=45)
        result = subprocess.run(['runuser', '-u', USER, '--', 'env',
                                 'SSH_ORIGINAL_COMMAND=sh -c id', str(SHELL)])
        if result.returncode != 126:
            raise RuntimeError('Unauthorized command was not rejected correctly.')
        print('Diagnostics v4 installed. Keys and existing account identity preserved on update.')
        print('Remote SSH validation still required. No service restart performed.')
    except BaseException:
        restore(saved)
        print('Previous files restored. A partially created new account requires administrator review.')
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Avoid dumping env contents or credential-bearing subprocess arguments.
        raise SystemExit('ERROR: Installation/update failed. Review prerequisites and backup; no secrets printed.')
