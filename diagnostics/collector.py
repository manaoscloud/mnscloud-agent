#!/usr/bin/python3
"""Fixed, bounded root collector. Never source env files; log text is always masked."""
from datetime import datetime, timezone
import json
import ipaddress
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
from urllib.parse import urlsplit

CONFIG_DIR = Path('/etc/mnscloud')
FILES = ('api', 'app', 'nginx', 'workers', 'rabbitmq', 'db', 'authentication', 'openvault')
UNITS = ('nginx', 'mariadb', 'rabbitmq-server', 'mnscloud-api',
         'mnscloud-workers', 'mnscloud-agent', 'asterisk', 'freeswitch', 'kamailio',
         'opensips', 'rtpengine-daemon', 'mnscloud-media-heartbeat', 'coturn',
         'mnscloud-turn-sync', 'mnscloud-webrtc-sync', 'mnscloud-authentication',
         'mnscloud-authentication-config', 'mnscloud-openvault', 'mnscloud-openvault-tls-renew',
         'mnscloud-webapps', 'mnscloud-webapps-sync', 'incus', 'mnscloud-grow-rootfs')
# Fixed log files readable through logs-text. Never accept paths from the client.
LOG_FILES = {
    'install': Path('/var/log/mnscloud-install.log'),
    'asterisk': Path('/var/log/asterisk/messages'),
    'freeswitch': Path('/var/log/freeswitch/freeswitch.log'),
    'kamailio-err': Path('/var/log/mnscloud/kamailio/kamailio.err.log'),
    'kamailio-out': Path('/var/log/mnscloud/kamailio/kamailio.out.log'),
    'turn': Path('/var/log/mnscloud/turn/turnserver.log'),
    'agent-install': Path('/var/log/mnscloud-agent-install.log'),
    # Engine log: subscriber usernames are replaced by [USER] before any other masking.
    'freeradius': Path('/var/log/freeradius/radius.log'),
}
USER_MASKED_LOGS = {'freeradius'}
BRACKETED = re.compile(r'\[[^\]]{0,256}\]')
# Root-controlled module checkouts reported by versions in addition to FILES.
CHECKOUTS = ('asterisk', 'freeswitch', 'kamailio-softswitch', 'opensips-sbc', 'media', 'turn',
             'kamailio-webrtc', 'webapps', 'agent')
LOG_TEXT_LINES = 120
LOG_TEXT_TAIL_BYTES = 262144
LOG_LINE_CHARS = 400
LOG_HIGHLIGHT_LINES = 80
LOG_HIGHLIGHT_CONTEXT = 3
# journal: one fixed unit, bounded window/priority, parameters only through stdin (never argv/sudo).
JOURNAL_LINES = 2000
JOURNAL_MAX_MINUTES = 1440
JOURNAL_DEFAULT_MINUTES = 60
JOURNAL_PRIORITIES = ('err', 'warning', 'notice', 'info')
JOURNAL_OUTPUT_BYTES = 4194304
JOURNAL_REQUEST_BYTES = 256
# Failure markers searched across the whole tail window, so a long post-failure summary
# cannot push the real cause out of the returned lines.
HIGHLIGHT = re.compile(r'(?i)\b(error|errors|failed|failure|fatal|panic|traceback|'
                       r'exception|denied|refused|timed out|segfault|killed|oom)\b|'
                       r'^E: |Last failed command|Installer failed|\[ERROR\]|ERROR\[')
REDACTED = '[REDACTED]'
# Ordered masking rules applied to every emitted log line.
MASKS = (
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*', re.S), REDACTED),
    (re.compile(r'(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]+'), r'\1\2' + REDACTED),
    (re.compile(r'eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}'), REDACTED),
    (re.compile(r'(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]*:[^/\s@]*@'), r'\1' + REDACTED + '@'),
    (re.compile(r'(?i)(\b[\w.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|private[_-]?key|'
                r'access[_-]?key|authorization|auth|credential|cookie|signature|salt)[\w.-]*'
                r'["\']?\s*(?:=|:|=>)\s*)(["\']?)[^\s"\'&,;]+'), r'\1\2' + REDACTED),
    (re.compile(r'(?i)(--(?:[\w-]*(?:pass|secret|token|key)[\w-]*)[= ]\s*)(["\']?)[^\s"\']+'),
     r'\1\2' + REDACTED),
    (re.compile(r'\b(?=[A-Za-z0-9+_-]*\d)(?=[A-Za-z0-9+_-]*[A-Za-z])[A-Za-z0-9+_-]{32,}={0,2}'), REDACTED),
)
# ANSI sequences first, then remaining control characters (terminal injection).
CONTROL = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]|[\x00-\x08\x0b-\x1f\x7f]')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
REQUIRED = {
    'api': ('DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS', 'JWT_SECRET', 'RABBITMQ_URL'),
    'app': ('APP_API_BASE_URL',),
    'nginx': ('MNSCLOUD_API_UPSTREAMS', 'MNSCLOUD_APP_UPSTREAMS'),
    'workers': ('RABBITMQ_URL', 'MNSCLOUD_API_BASE_URL', 'MNSCLOUD_WORKER_NODE_NAME'),
    'rabbitmq': ('RABBITMQ_DEFAULT_USER', 'RABBITMQ_DEFAULT_PASS',
                 'MNSCLOUD_API_BASE_URL', 'MNSCLOUD_RABBITMQ_QUEUE_SOURCE'),
    'db': ('DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_ROOT_PASSWORD'),
    'authentication': ('MNSCLOUD_API_BASE_URL', 'AUTHENTICATION_SERVER_UUID',
                       'AUTHENTICATION_LISTEN_ADDRESS', 'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS'),
    'openvault': ('OPENVAULT_MODE', 'OPENVAULT_PRIVATE_HOST', 'OPENVAULT_NODE_ID'),
}
HOST_KEYS = {'DB_HOST', 'APP_HOST', 'APP_LISTEN_ADDR', 'MNSCLOUD_API_LISTEN_ADDR',
             'MNSCLOUD_PRIMARY_DOMAIN', 'MNSCLOUD_API_DOMAIN', 'MNSCLOUD_WEBSITE_DOMAIN',
             'MNSCLOUD_RABBITMQ_HOSTNAME', 'MNSCLOUD_NODE_ADDRESS',
             'AUTHENTICATION_LISTEN_ADDRESS', 'OPENVAULT_PRIVATE_HOST'}
PORT_KEYS = {'DB_PORT', 'APP_PORT', 'APP_LISTEN_PORT', 'MNSCLOUD_API_LISTEN_PORT',
             'MNSCLOUD_RABBITMQ_AMQP_PORT', 'MNSCLOUD_RABBITMQ_MANAGEMENT_PORT'}
URL_KEYS = {'RABBITMQ_URL', 'MNSCLOUD_API_BASE_URL', 'APP_API_BASE_URL',
            'MNSCLOUD_RELEASE_API_BASE_URL', 'MNSCLOUD_APP_UPSTREAMS',
            'MNSCLOUD_API_UPSTREAMS', 'MNSCLOUD_WEBSITE_UPSTREAM',
            'MNSCLOUD_WEBAPPS_UPSTREAM', 'MNSCLOUD_RABBITMQ_UPSTREAM',
            'MNSCLOUD_MESSAGING_QUEUES_URL'}
ENUMS = {'DENO_ENV': {'production', 'staging', 'development'},
         'MNSCLOUD_DB_MODE': {'standalone', 'cluster'},
         'MNSCLOUD_RABBITMQ_QUEUE_SOURCE': {'api', 'fallback'}}
BOOL_KEYS = {'APP_DEBUG', 'MNSCLOUD_ENABLE_WEBAPPS_PROXY',
             'MNSCLOUD_ENABLE_RABBITMQ_PROXY', 'MNSCLOUD_ENABLE_CERTBOT'}
NAME_KEYS = {'DB_NAME', 'DB_USER', 'RABBITMQ_DEFAULT_USER',
             'MNSCLOUD_WORKER_NODE_NAME', 'MNSCLOUD_RABBITMQ_NODE_NAME',
             'MNSCLOUD_NODE_NAME', 'MNSCLOUD_CLUSTER_NAME', 'AUTHENTICATION_SERVER_UUID',
             'OPENVAULT_MODE', 'OPENVAULT_NODE_ID', 'OPENVAULT_TLS_MODE', 'OPENVAULT_SEAL',
             'OPENVAULT_AWSKMS_REGION', 'OPENVAULT_OPENBAO_VERSION', 'OPENVAULT_RUNTIME_KIT_CHANNEL',
             'OPENVAULT_AGENT_INSTALL_LABEL'}
NUMBER_KEYS = {'WORKER_PREFETCH', 'WORKER_CONNECT_RETRIES', 'WORKER_CONNECT_RETRY_MS',
               'WORKER_AGENT_HEALTH_SCAN_INTERVAL_MS', 'WORKER_AGENT_HEALTH_BATCH_LIMIT',
               'WORKER_AGENT_HEALTH_DEGRADED_AFTER_SECONDS',
               'WORKER_AGENT_HEALTH_OFFLINE_AFTER_SECONDS', 'BCRYPT_SALT_ROUNDS'}


def trusted_read(path):
    """Reject symlinks, writable ancestors, special files and oversized inputs."""
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe file ownership or permissions')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise ValueError('Unsupported file type or size')
        text = stream.read(65537)
        if len(text) > 65536:
            raise ValueError('Input too large')
        return text


def parse_env(text):
    result = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:]
        key, sep, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not sep or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}', key):
            raise ValueError('Unsupported env syntax')
        if key in result:
            raise ValueError('Duplicate env key')
        if value[:1] in ('"', "'"):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError('Unsupported multiline or quoted value')
            value = value[1:-1]
        result[key] = value
    return result


def load_configs():
    result = {}
    for name in FILES:
        try:
            result[name] = parse_env(trusted_read(CONFIG_DIR / (name + '.env')))
        except FileNotFoundError:
            result[name] = None
        except (OSError, ValueError, UnicodeError):
            result[name] = 'UNREADABLE_OR_UNSAFE'
    return result


def endpoints(value):
    result = []
    for part in value.split(',')[:8]:
        url = urlsplit(part.strip())
        if url.scheme not in ('http', 'https', 'amqp', 'amqps') or not url.hostname:
            raise ValueError('Unsupported endpoint')
        host = url.hostname
        if not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', host):
            raise ValueError('Invalid hostname')
        port = url.port or {'http': 80, 'https': 443, 'amqp': 5672, 'amqps': 5671}[url.scheme]
        if not 1 <= port <= 65535:
            raise ValueError('Invalid port')
        # Userinfo, paths, queries and fragments are deliberately never returned.
        result.append({'scheme': url.scheme, 'host': host, 'port': port})
    return result


def public_value(key, value):
    if not value:
        return 'EMPTY'
    if key in URL_KEYS:
        try:
            return endpoints(value)
        except ValueError:
            return 'INVALID_ENDPOINT'
    if key in HOST_KEYS and re.fullmatch(r'[A-Za-z0-9.*:-]{1,253}', value):
        return value
    if key in PORT_KEYS and value.isdecimal() and 1 <= int(value) <= 65535:
        return int(value)
    if key in ENUMS and value in ENUMS[key]:
        return value
    if key in BOOL_KEYS and value in ('true', 'false'):
        return value == 'true'
    if key in NAME_KEYS and re.fullmatch(r'[A-Za-z0-9_@.-]{1,100}', value):
        return value
    if key in NUMBER_KEYS and re.fullmatch(r'[0-9]{1,9}', value):
        return int(value)
    if key == 'WORKER_HANDLERS':
        handlers = value.split(',')
        if all(x in {'smtp', 'vps', 'vps-container', 'webhost', 'storage',
                     'pabx-control', 'agent-health', 'activity-log'} for x in handlers):
            return handlers
    if key == 'MNSCLOUD_TRUSTED_PROXY_CIDRS':
        try:
            return [str(ipaddress.ip_network(x.strip(), strict=False)) for x in value.split(',')[:16]]
        except ValueError:
            return 'INVALID_CIDR'
    if key == 'CORS_ALLOWED_ORIGINS':
        try:
            return endpoints(value)
        except ValueError:
            return 'INVALID_ENDPOINT'
    # All other fields, including new/unknown settings and credentials, fail closed.
    return 'SET'


def config_report(configs, checks=False):
    output = {}
    for name, values in configs.items():
        if not isinstance(values, dict):
            output[name] = values or 'MISSING_FILE'
            continue
        if not checks:
            output[name] = {key: public_value(key, value) for key, value in values.items()}
            continue
        issues = []
        required = list(REQUIRED[name])
        if name == 'workers' and any(x in values.get('WORKER_HANDLERS', '').split(',')
                                     for x in ('agent-health', 'activity-log')):
            required += ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS']
        if name == 'rabbitmq' and values.get('MNSCLOUD_RABBITMQ_QUEUE_SOURCE') == 'api':
            required += ['MNSCLOUD_MESSAGING_REGISTRY_TOKEN']
        for key in required:
            if key == 'APP_API_BASE_URL':
                continue  # Empty or absent means same-origin.
            if not values.get(key):
                issues.append({'key': key, 'status': 'EMPTY' if key in values else 'MISSING'})
        for key, value in values.items():
            if key in URL_KEYS and value and public_value(key, value) == 'INVALID_ENDPOINT':
                issues.append({'key': key, 'status': 'INVALID_ENDPOINT'})
            if key in PORT_KEYS and (not value.isdecimal() or not 1 <= int(value) <= 65535):
                issues.append({'key': key, 'status': 'INVALID_PORT'})
            if key in ENUMS and value not in ENUMS[key]:
                issues.append({'key': key, 'status': 'INVALID_ENUM'})
        if name == 'api' and values.get('DENO_ENV') == 'production' and values.get('APP_DEBUG') != 'false':
            issues.append({'key': 'APP_DEBUG', 'status': 'DISABLE_IN_PRODUCTION'})
        output[name] = {'issues': issues, 'scope': 'STATIC_CHECK_ONLY'}
    return output


def run(args, limit=262144, timeout=12):
    # File-backed bounded reads avoid buffering an unbounded command response in RAM.
    import tempfile
    with tempfile.TemporaryFile() as output:
        subprocess.run(args, stdout=output, stderr=subprocess.DEVNULL,
                       env=ENV, timeout=timeout, check=True)
        output.seek(0)
        data = output.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Output too large')
        return data.decode('utf-8', errors='replace')


def summarize_logs(text):
    events = []
    for line in text.splitlines():
        row = json.loads(line)
        message = str(row.get('MESSAGE', '')).lower()
        category = 'OTHER_MESSAGE_REDACTED'
        for word, label in (('out of memory', 'MEMORY'), ('access denied', 'AUTHENTICATION'),
                            ('unauthorized', 'AUTHENTICATION'), ('connection refused', 'CONNECTION'),
                            ('timed out', 'TIMEOUT'), ('timeout', 'TIMEOUT'),
                            ('certificate', 'TLS'), ('error', 'ERROR'), ('failed', 'FAILURE')):
            if word in message:
                category = label
                break
        timestamp = str(row.get('__REALTIME_TIMESTAMP', ''))
        priority = str(row.get('PRIORITY', ''))
        events.append({'timestamp_us': timestamp if timestamp.isdecimal() else None,
                       'priority': priority if priority in tuple('01234567') else None,
                       'category': category})
    return events[-40:]


def logs():
    output = {}
    for unit in UNITS:
        try:
            text = run(['/usr/bin/journalctl', '--no-pager', '--output=json',
                        '--since=-15min', '--lines=40', '--unit=' + unit + '.service'])
            output[unit] = summarize_logs(text)
        except (OSError, ValueError, subprocess.SubprocessError):
            output[unit] = 'UNAVAILABLE'
    return output


def mask_line(line):
    text = CONTROL.sub('', line)
    for pattern, replacement in MASKS:
        text = pattern.sub(replacement, text)
    if len(text) > LOG_LINE_CHARS:
        text = text[:LOG_LINE_CHARS] + ' [TRUNCATED]'
    return text


def tail_log(path, mask_users=False):
    """Read the end of a fixed log without following links planted by service users."""
    for parent in reversed(path.parents):
        if stat.S_ISLNK(parent.lstat().st_mode):
            raise ValueError('Symlinked log directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        # A hard link could expose another file (for example /etc/shadow) through a log name.
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Unsupported log file type')
        stream.seek(max(0, info.st_size - LOG_TEXT_TAIL_BYTES))
        data = stream.read(LOG_TEXT_TAIL_BYTES)
    lines = data.decode('utf-8', errors='replace').splitlines()
    if info.st_size > LOG_TEXT_TAIL_BYTES and lines:
        lines = lines[1:]  # Drop the partial first line of the window.
    if mask_users:
        lines = [BRACKETED.sub('[USER]', line) for line in lines]
    return {'tail': [mask_line(line) for line in lines[-LOG_TEXT_LINES:]],
            'highlights': highlights(lines)}


def highlights(lines):
    """Failure lines with short preceding context, oldest first, bounded and masked."""
    picked = set()
    for index, line in enumerate(lines):
        if HIGHLIGHT.search(line):
            picked.update(range(max(0, index - LOG_HIGHLIGHT_CONTEXT), index + 1))
    output, previous = [], None
    for index in sorted(picked):
        if previous is not None and index != previous + 1:
            output.append('...')
        output.append(str(index + 1) + ': ' + mask_line(lines[index]))
        previous = index
    return output[-LOG_HIGHLIGHT_LINES:]


def journal_text(text):
    lines = []
    for raw in text.splitlines():
        row = json.loads(raw)
        message = row.get('MESSAGE', '')
        if isinstance(message, list):
            message = bytes(x for x in message if isinstance(x, int) and 0 <= x < 256).decode('utf-8', errors='replace')
        timestamp = str(row.get('__REALTIME_TIMESTAMP', ''))
        prefix = timestamp if timestamp.isdecimal() else '-'
        lines.append(prefix + ' ' + mask_line(str(message)))
    return lines[-LOG_TEXT_LINES:]


def logs_text():
    output = {'files': {}, 'journal': {}}
    for name, path in LOG_FILES.items():
        try:
            output['files'][name] = tail_log(path, name in USER_MASKED_LOGS)
        except FileNotFoundError:
            output['files'][name] = 'MISSING_FILE'
        except (OSError, ValueError):
            output['files'][name] = 'UNREADABLE_OR_UNSAFE'
    for unit in UNITS:
        try:
            text = run(['/usr/bin/journalctl', '--no-pager', '--output=json',
                        '--since=-60min', '--lines=' + str(LOG_TEXT_LINES),
                        '--unit=' + unit + '.service'])
            output['journal'][unit] = journal_text(text)
        except (OSError, ValueError, subprocess.SubprocessError):
            output['journal'][unit] = 'UNAVAILABLE'
    output['masking'] = 'SECRETS_TOKENS_AND_KEYS_REDACTED_BEST_EFFORT'
    return output


def parse_journal_request(text):
    """Validate `UNIT [MINUTES] [PRIORITY]`; anything else is rejected before journalctl runs."""
    if text.endswith('\n'):
        text = text[:-1]
    if not text or len(text) > JOURNAL_REQUEST_BYTES or not re.fullmatch(r'[a-z0-9-]+(?: [a-z0-9]+){0,2}', text):
        raise PermissionError('Unsupported journal request')
    tokens = text.split(' ')
    unit, minutes, priority = tokens.pop(0), JOURNAL_DEFAULT_MINUTES, 'info'
    if unit not in UNITS:
        raise PermissionError('Unsupported journal unit')
    if tokens and tokens[0].isdecimal():
        minutes = int(tokens.pop(0))
        if not 1 <= minutes <= JOURNAL_MAX_MINUTES:
            raise PermissionError('Unsupported journal window')
    if tokens:
        priority = tokens.pop(0)
        if priority not in JOURNAL_PRIORITIES:
            raise PermissionError('Unsupported journal priority')
    if tokens:
        raise PermissionError('Unsupported journal request')
    return unit, minutes, priority


def journal_lines(text):
    lines = []
    for raw in text.splitlines():
        row = json.loads(raw)
        message = row.get('MESSAGE', '')
        if isinstance(message, list):
            message = bytes(x for x in message if isinstance(x, int) and 0 <= x < 256).decode('utf-8', errors='replace')
        stamp = str(row.get('__REALTIME_TIMESTAMP', ''))
        when = (datetime.fromtimestamp(int(stamp) / 1e6, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                if stamp.isdecimal() else '-')
        level = str(row.get('PRIORITY', ''))
        lines.append(when + ' ' + (level if level.isdecimal() else '-') + ' ' + mask_line(str(message)))
    return lines


def journal(request):
    unit, minutes, priority = parse_journal_request(request)
    try:
        text = run(['/usr/bin/journalctl', '--no-pager', '--output=json',
                    '--output-fields=MESSAGE,PRIORITY', '--since=-' + str(minutes) + 'min',
                    '--priority=' + priority, '--lines=' + str(JOURNAL_LINES),
                    '--unit=' + unit + '.service'], limit=JOURNAL_OUTPUT_BYTES, timeout=30)
        lines = journal_lines(text)
    except ValueError:
        lines = 'OUTPUT_TOO_LARGE'
    except (OSError, subprocess.SubprocessError):
        lines = 'UNAVAILABLE'
    return {'unit': unit, 'sinceMinutes': minutes, 'priority': priority,
            'lineLimit': JOURNAL_LINES, 'lines': lines,
            'limitReached': isinstance(lines, list) and len(lines) >= JOURNAL_LINES,
            'masking': 'SECRETS_TOKENS_AND_KEYS_REDACTED_BEST_EFFORT'}


def versions():
    output = {'diagnostics': '3.7'}
    for package in ('nginx', 'mariadb-server', 'rabbitmq-server', 'docker-ce',
                    'freeswitch', 'kamailio', 'opensips', 'rtpengine-daemon', 'coturn',
                    'freeradius', 'incus'):
        try:
            value = run(['/usr/bin/dpkg-query', '-W', '-f=${Version}', package]).strip()
            output[package] = value if re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,100}', value) else 'UNKNOWN'
        except (OSError, ValueError, subprocess.SubprocessError):
            output[package] = 'UNAVAILABLE'
    for name in (*FILES, *CHECKOUTS):
        path = Path('/opt/mnscloud') / ('mnscloud-' + name) / 'VERSION'
        try:
            value = trusted_read(path).strip()
            output[name + '_checkout_version'] = value if re.fullmatch(r'v?\d+\.\d+\.\d+[-A-Za-z0-9.]*', value) else 'UNKNOWN'
        except (OSError, ValueError, UnicodeError):
            output[name + '_checkout_version'] = 'UNAVAILABLE'
    output['note'] = 'Checkout version does not prove deployed artifact identity.'
    return output


def parse_odbc_show(text):
    """Connection names and pool counters from `odbc show`; DSN values are never returned."""
    pools, current = [], None
    for line in text.splitlines():
        line = line.strip()
        name = re.fullmatch(r'Name:\s*(\S+)', line)
        if name:
            value = name.group(1)
            current = {'name': value if re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value) else 'REDACTED',
                       'active': None, 'max': None}
            pools.append(current)
            continue
        counts = re.fullmatch(r'Number of active connections:\s*(\d{1,6})\s*\(out of\s*(\d{1,6})\)', line)
        if counts and current is not None:
            current['active'], current['max'] = int(counts.group(1)), int(counts.group(2))
    for pool in pools:
        pool['status'] = ('CONNECTED' if pool['active'] else
                          'NO_ACTIVE_CONNECTION' if pool['active'] == 0 else 'UNKNOWN')
    return pools[:8]


def asterisk_odbc():
    # Asks the running Asterisk for its own ODBC pool state; no SQL, no credentials, no DSN.
    try:
        pools = parse_odbc_show(run(['/usr/sbin/asterisk', '-rx', 'odbc show']))
        status = 'OK' if pools else 'NO_ODBC_POOLS'
    except (OSError, ValueError, subprocess.SubprocessError):
        pools, status = [], 'ASTERISK_UNAVAILABLE'
    return {'status': status, 'pools': pools,
            'scope': 'ASTERISK_POOL_STATE_ONLY_NO_SQL_OR_CREDENTIALS'}


def connectivity(configs):
    targets = []
    for name, values in configs.items():
        if not isinstance(values, dict):
            continue
        for key in sorted(URL_KEYS):
            if values.get(key):
                try:
                    targets.extend(endpoints(values[key]))
                except ValueError:
                    pass
        if values.get('DB_HOST') and re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', values['DB_HOST']):
            try:
                port = int(values.get('DB_PORT', '3306'))
                if 1 <= port <= 65535:
                    targets.append({'scheme': 'tcp', 'host': values['DB_HOST'], 'port': port})
            except ValueError:
                pass
    output, seen = [], set()
    for target in targets:
        identity = tuple(target.values())
        if identity in seen:
            continue
        seen.add(identity)
        result = dict(target)
        try:
            with socket.create_connection((target['host'], target['port']), timeout=2) as sock:
                if target['scheme'] in ('https', 'amqps'):
                    context = ssl.create_default_context()
                    context.minimum_version = ssl.TLSVersion.TLSv1_2  # never report legacy TLS as healthy
                    with context.wrap_socket(sock, server_hostname=target['host']):
                        pass
                result['status'] = 'TLS_OK' if target['scheme'] in ('https', 'amqps') else 'TCP_OK'
        except (OSError, ValueError):
            result['status'] = 'CONNECTION_OR_TLS_FAILED'
        output.append(result)
        if len(output) >= 12:
            break
    return {'targets': output, 'scope': 'TCP_TLS_ONLY_NO_AUTHENTICATION_OR_SQL'}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('config', 'config-check', 'logs', 'logs-text', 'journal', 'versions',
                                                      'connectivity', 'asterisk-odbc'):
        print('DENIED: Unsupported collector operation.', file=sys.stderr)
        return 126
    signal.alarm(40)
    request = None
    if sys.argv[1] == 'journal':
        try:
            request = sys.stdin.buffer.read(JOURNAL_REQUEST_BYTES + 2).decode('ascii')
            parse_journal_request(request)
        except (PermissionError, UnicodeDecodeError):
            print('DENIED: Unsupported journal request. Use: journal UNIT [MINUTES] [PRIORITY].', file=sys.stderr)
            return 126
    if os.geteuid() != 0:
        print('ERROR: Collector requires its dedicated sudo rule.', file=sys.stderr)
        return 1
    os.umask(0o077)
    operation = sys.argv[1]
    if operation == 'journal':
        result = journal(request)
    elif operation == 'logs':
        result = logs()
    elif operation == 'logs-text':
        result = logs_text()
    elif operation == 'versions':
        result = versions()
    elif operation == 'asterisk-odbc':
        result = asterisk_odbc()
    else:
        configs = load_configs()
        result = connectivity(configs) if operation == 'connectivity' else config_report(configs, operation == 'config-check')
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        print('ERROR: Diagnostic collection failed; raw details suppressed.', file=sys.stderr)
        sys.exit(1)
