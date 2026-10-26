#!/usr/bin/python3
"""Fixed, bounded root collector. Never source env files; log text is always masked."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import base64
import gzip
import time
import hashlib
import http.client
import json
import ipaddress
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
from urllib.parse import urlsplit

DIAGNOSTICS_VERSION = '4.4'
DIAGNOSTICS_USER = 'mns-diagnostics'
CONFIG_DIR = Path('/etc/mnscloud')
FILES = ('api', 'app', 'nginx', 'workers', 'rabbitmq', 'db', 'authentication', 'openvault', 'logs', 'dns')
UNITS = ('nginx', 'mariadb', 'rabbitmq-server', 'mnscloud-api',
         'mnscloud-workers', 'mnscloud-agent', 'asterisk', 'freeswitch', 'kamailio',
         'opensips', 'rtpengine-daemon', 'mnscloud-media-heartbeat', 'coturn',
         'mnscloud-turn-sync', 'mnscloud-webrtc-sync', 'mnscloud-authentication',
         'mnscloud-authentication-config', 'mnscloud-openvault', 'mnscloud-openvault-tls-renew',
         'mnscloud-webapps', 'mnscloud-webapps-sync', 'incus', 'mnscloud-grow-rootfs',
         'mnscloud-logs-storage', 'mnscloud-logs-ingest', 'mnscloud-logs-config',
         'pdns', 'pdns-recursor', 'dnsdist', 'mnscloud-dns-config')
# Any installed MNSCloud unit is covered without a diagnostics release (diagnostics 4.0): names are
# validated against this pattern before they reach systemctl/journalctl.
MNSCLOUD_UNIT = re.compile(r'mnscloud-[a-z0-9]+(?:-[a-z0-9]+){0,8}')
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
DB_RELEASES = Path('/opt/mnscloud/mnscloud-db-releases')
DB_RELEASE = re.compile(r'v(\d+\.\d+\.\d+)-[a-f0-9]{64}')
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
# container-logs (diagnostics 4.2): one mnscloud-* Docker container (the worker runs in Compose, so
# its application output never reaches the journal), bounded window, parameters only through stdin.
CONTAINER = re.compile(r'mnscloud-[a-z0-9]+(?:-[a-z0-9]+){0,8}')
CONTAINER_DEFAULT_MINUTES = 60
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
    # Node principals live in logs-secrets.env, which diagnostics never reads.
    'logs': ('MNSCLOUD_API_BASE_URL', 'LOGS_SERVER_UUID', 'LOGS_ROLE', 'LOGS_LISTEN_ADDRESS',
             'LOGS_SYSLOG_UDP_PORT', 'LOGS_SYSLOG_TCP_PORT'),
    # Engine API keys live in dns-secrets.env, which diagnostics never reads.
    'dns': ('MNSCLOUD_API_BASE_URL', 'DNS_SERVER_UUID', 'DNS_ROLES', 'DNS_NODE_ADDRESS'),
}
HOST_KEYS = {'DB_HOST', 'APP_HOST', 'APP_LISTEN_ADDR', 'MNSCLOUD_API_LISTEN_ADDR',
             'MNSCLOUD_PRIMARY_DOMAIN', 'MNSCLOUD_API_DOMAIN', 'MNSCLOUD_WEBSITE_DOMAIN',
             'MNSCLOUD_RABBITMQ_HOSTNAME', 'MNSCLOUD_NODE_ADDRESS',
             'AUTHENTICATION_LISTEN_ADDRESS', 'OPENVAULT_PRIVATE_HOST', 'LOGS_LISTEN_ADDRESS',
             'DNS_NODE_ADDRESS'}
PORT_KEYS = {'DB_PORT', 'APP_PORT', 'APP_LISTEN_PORT', 'MNSCLOUD_API_LISTEN_PORT',
             'MNSCLOUD_RABBITMQ_AMQP_PORT', 'MNSCLOUD_RABBITMQ_MANAGEMENT_PORT',
             'LOGS_SYSLOG_UDP_PORT', 'LOGS_SYSLOG_TCP_PORT'}
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


def run(args, limit=262144, timeout=12, stderr=False):
    # File-backed bounded reads avoid buffering an unbounded command response in RAM.
    import tempfile
    with tempfile.TemporaryFile() as output:
        subprocess.run(args, stdout=output, stderr=subprocess.STDOUT if stderr else subprocess.DEVNULL,
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


def installed_units():
    """Fixed units plus every installed mnscloud-* service, validated before any later use."""
    found = []
    try:
        text = run(['/usr/bin/systemctl', '--no-pager', '--plain', '--no-legend', '--all',
                    'list-units', '--type=service', 'mnscloud-*'], limit=65536, timeout=10)
        for line in text.splitlines():
            name = line.split(' ', 1)[0].strip()
            if name.endswith('.service') and MNSCLOUD_UNIT.fullmatch(name[:-8]):
                found.append(name[:-8])
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return tuple(dict.fromkeys((*UNITS, *sorted(found)[:64])))


def logs():
    output = {}
    for unit in installed_units():
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
    for unit in installed_units():
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
    if unit not in UNITS and not MNSCLOUD_UNIT.fullmatch(unit):
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



def parse_container_request(text):
    """Validate `CONTAINER [MINUTES]`; anything else is rejected before docker runs."""
    if text.endswith('\n'):
        text = text[:-1]
    if not text or len(text) > JOURNAL_REQUEST_BYTES or not re.fullmatch(r'[a-z0-9-]+(?: [0-9]+)?', text):
        raise PermissionError('Unsupported container-logs request')
    name, _, window = text.partition(' ')
    if not CONTAINER.fullmatch(name):
        raise PermissionError('Unsupported container')
    minutes = int(window) if window else CONTAINER_DEFAULT_MINUTES
    if not 1 <= minutes <= JOURNAL_MAX_MINUTES:
        raise PermissionError('Unsupported container-logs window')
    return name, minutes


def container_lines(text):
    """Masked lines ordered by Docker's RFC 3339 timestamp (stdout and stderr arrive apart)."""
    lines = [mask_line(line) for line in text.splitlines() if line.strip()]
    return sorted(lines, key=lambda line: line.split(' ', 1)[0])[-JOURNAL_LINES:]


def container_logs(request, runner=run):
    name, minutes = parse_container_request(request)
    try:
        text = runner(['/usr/bin/docker', 'logs', '--timestamps', '--since', str(minutes) + 'm',
                       '--tail', str(JOURNAL_LINES), name], limit=JOURNAL_OUTPUT_BYTES, timeout=30, stderr=True)
        lines = container_lines(text)
    except ValueError:
        lines = 'OUTPUT_TOO_LARGE'
    except (OSError, subprocess.SubprocessError):
        lines = 'UNAVAILABLE'
    return {'container': name, 'sinceMinutes': minutes, 'lineLimit': JOURNAL_LINES, 'lines': lines,
            'limitReached': isinstance(lines, list) and len(lines) >= JOURNAL_LINES,
            'masking': 'SECRETS_TOKENS_AND_KEYS_REDACTED_BEST_EFFORT'}

def versions():
    output = {'diagnostics': DIAGNOSTICS_VERSION}
    for package in ('nginx', 'mariadb-server', 'rabbitmq-server', 'docker-ce',
                    'freeswitch', 'kamailio', 'opensips', 'rtpengine-daemon', 'coturn',
                    'freeradius', 'incus', 'clickhouse-server', 'vector', 'pdns-server', 'pdns-recursor',
                    'dnsdist'):
        try:
            value = run(['/usr/bin/dpkg-query', '-W', '-f=${Version}', package]).strip()
            output[package] = value if re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,100}', value) else 'UNKNOWN'
        except (OSError, ValueError, subprocess.SubprocessError):
            output[package] = 'UNAVAILABLE'
    for name in (*FILES, *CHECKOUTS):
        if name == 'db':
            continue
        path = Path('/opt/mnscloud') / ('mnscloud-' + name) / 'VERSION'
        try:
            value = trusted_read(path).strip()
            output[name + '_checkout_version'] = value if re.fullmatch(r'v?\d+\.\d+\.\d+[-A-Za-z0-9.]*', value) else 'UNKNOWN'
        except (OSError, ValueError, UnicodeError):
            output[name + '_checkout_version'] = 'UNAVAILABLE'
    output['db_release_version'] = db_release_version()
    output['note'] = 'Checkout version does not prove deployed artifact identity.'
    return output


def db_release_version(parent=DB_RELEASES):
    """Newest approved DB release prepared by schema reconcile; the base checkout is only its git source."""
    if not parent.is_dir():
        return 'UNAVAILABLE'
    try:
        for item in (*reversed(parent.parents), parent):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return 'UNKNOWN'
        tags = [match.group(1) for match in (DB_RELEASE.fullmatch(entry.name) for entry in parent.iterdir())
                if match]
    except OSError:
        return 'UNAVAILABLE'
    if not tags:
        return 'UNAVAILABLE'
    return max(tags, key=lambda tag: tuple(int(part) for part in tag.split('.')))


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


# --- diagnostics 4.0 -------------------------------------------------------------------------------

def drop_privileges():
    """Become the unprivileged diagnostics account; used before reads that need no root and before
    any network or database I/O, so a parsing or protocol bug never runs with root rights."""
    try:
        account = pwd.getpwnam(DIAGNOSTICS_USER)
    except KeyError:
        raise PermissionError('Diagnostics account missing') from None
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise PermissionError('Diagnostics account must not be privileged')
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    if os.geteuid() == 0 or os.getegid() == 0:
        raise PermissionError('Privileges were not dropped')


VERSION_TEXT = re.compile(r'v?\d+\.\d+\.\d+[-A-Za-z0-9.+]{0,40}')
SAFE_SCALAR = re.compile(r'[A-Za-z0-9 _.:/@+~,=()-]{0,160}')
HEX_REF = re.compile(r'[a-f0-9]{7,64}')
BUILD_FIELDS = ('product', 'app', 'version', 'ref', 'gitRef', 'buildRef', 'buildDate', 'minimumVersion',
                'updateChannel')
APP_ROOT = Path('/var/www/mnscloud-app')
WEBAPPS_ROOT = Path('/opt/mnscloud/webapps')
AGENT_INSTALL = Path('/opt/mnscloud/agent')
# Runtime products whose checkout the Agent reports as installed (main.ts collectRuntimeVersions).
RUNTIME_CHECKOUTS = ('api', 'app', 'nginx', 'rabbitmq', 'workers', 'authentication', 'logs', 'dns', 'freeswitch',
                     'asterisk', 'opensips-sbc', 'kamailio-softswitch', 'kamailio-webrtc', 'turn', 'media',
                     'webapps', 'openvault')


def safe_scalar(value):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and abs(value) < 10 ** 15:
        return value
    if isinstance(value, float) and abs(value) < 10 ** 15:
        return round(value, 3)
    text = str(value)
    return text if SAFE_SCALAR.fullmatch(text) else 'REDACTED'


def public_read(path, limit=65536):
    """Bounded read of a world-readable artifact file as the unprivileged account (no link follow)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('Unsupported artifact file')
        return stream.read(limit + 1)


def build_metadata(directory):
    """version/ref/buildRef of build.json (VERSION as fallback), the fields the Agent itself reports."""
    result = {}
    try:
        data = json.loads(public_read(directory / 'build.json'))
        if isinstance(data, dict):
            for key in BUILD_FIELDS:
                if key in data:
                    result[key] = safe_scalar(data[key])
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError):
        result['build'] = 'UNREADABLE_OR_UNSAFE'
    if 'version' not in result:
        try:
            value = public_read(directory / 'VERSION', 256).decode('ascii').strip()
            result['version'] = value if VERSION_TEXT.fullmatch(value) else 'UNKNOWN'
        except FileNotFoundError:
            pass
        except (OSError, ValueError, UnicodeError):
            result['version'] = 'UNREADABLE_OR_UNSAFE'
    return result or 'NO_VERSION_METADATA'


def file_sha256(path, limit=4194304):
    try:
        return hashlib.sha256(public_read(path, limit)).hexdigest()
    except (OSError, ValueError):
        return 'UNAVAILABLE'


def webapps_artifacts(root=WEBAPPS_ROOT):
    current = root / 'current'
    if not current.is_dir():
        return 'NOT_INSTALLED'
    output = {}
    for entry in sorted(current.iterdir())[:32]:
        name = entry.name
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', name):
            continue
        # current/<app> links to releases/<app>/<release>; anything outside that tree is reported, not read.
        target = Path(os.path.realpath(entry))
        releases = (root / 'releases' / name).resolve()
        if target.parent != releases:
            output[name] = 'UNEXPECTED_RELEASE_TARGET'
            continue
        item = build_metadata(target)
        item = item if isinstance(item, dict) else {'build': item}
        item['release'] = target.name if re.fullmatch(r'[A-Za-z0-9._-]{1,120}', target.name) else 'REDACTED'
        item['indexSha256'] = file_sha256(target / 'index.html')
        output[name] = item
    return output


def artifacts():
    """What each host serves or runs right now, read as the unprivileged account."""
    output = {'diagnostics': DIAGNOSTICS_VERSION, 'served': {}, 'checkouts': {}}
    if APP_ROOT.is_dir():
        item = build_metadata(APP_ROOT)
        item = item if isinstance(item, dict) else {'build': item}
        item['indexSha256'] = file_sha256(APP_ROOT / 'index.html')
        output['served']['mnscloud-app'] = item
    output['webapps'] = webapps_artifacts()
    for name in RUNTIME_CHECKOUTS:
        directory = Path('/opt/mnscloud') / ('mnscloud-' + name)
        if directory.is_dir():
            output['checkouts']['mnscloud-' + name] = build_metadata(directory)
    output['agent'] = build_metadata(AGENT_INSTALL) if AGENT_INSTALL.is_dir() else 'NOT_INSTALLED'
    output['db_release_version'] = db_release_version()
    output['note'] = ('served = files the web server returns; checkouts = what the Agent reports as installed '
                      '(build.json or VERSION of /opt/mnscloud/mnscloud-*).')
    return output


# health: fixed local endpoints only. Hosts must be addresses of this machine, paths are constants and
# only listed response fields are returned. Configuration is read as root, requests run unprivileged.
HEALTH_FIELDS = {
    'api': ('status', 'database', 'openvault', 'version', 'environment'),
    'app': ('product', 'version', 'gitRef', 'buildRef', 'buildDate'),
    'webapps': (),
    'openvault': ('initialized', 'sealed', 'standby', 'version'),
    'logs-clickhouse': (),
    'logs-vector': (),
}
WEBAPPS_ENV = CONFIG_DIR / 'webapps' / 'webapps.env'
OPENVAULT_HEALTH = '/v1/sys/health?standbyok=true&perfstandbyok=true&sealedcode=200&uninitcode=200'


def local_address(host):
    """Loopback, or an address assigned to this host (bind succeeds only for local addresses)."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.is_unspecified:
        return '::1' if address.version == 6 else '127.0.0.1'
    if address.is_loopback:
        return str(address)
    if address.is_multicast or address.is_link_local:
        return None
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((str(address), 0))
    except OSError:
        return None
    return str(address)


def env_port(values, key, default):
    value = (values or {}).get(key, '') if isinstance(values, dict) else ''
    if not value:
        return default
    return int(value) if value.isdecimal() and 1 <= int(value) <= 65535 else None


def health_targets(configs, webapps_env, app_installed):
    targets = []

    def add(name, scheme, host, port, path):
        address = local_address(host) if host else None
        targets.append({'name': name, 'scheme': scheme, 'host': address, 'port': port, 'path': path,
                        'configError': None if address and port else 'NOT_A_LOCAL_ADDRESS_OR_PORT'})

    api = configs.get('api')
    if isinstance(api, dict):
        add('api', 'http', api.get('APP_HOST') or '127.0.0.1', env_port(api, 'APP_PORT', 8000), '/api/v1/health')
    app = configs.get('app')
    if isinstance(app, dict) or app_installed:
        values = app if isinstance(app, dict) else {}
        add('app', 'http', values.get('APP_LISTEN_ADDR') or '127.0.0.1', env_port(values, 'APP_LISTEN_PORT', 8080),
            '/build.json')
    if isinstance(webapps_env, dict):
        add('webapps', 'http', webapps_env.get('WEBAPPS_LISTEN_HOST') or '127.0.0.1',
            env_port(webapps_env, 'WEBAPPS_LISTEN_PORT', 8080), '/healthz')
    if isinstance(configs.get('openvault'), dict):
        add('openvault', 'https', '127.0.0.1', 8200, OPENVAULT_HEALTH)
    if isinstance(configs.get('logs'), dict):
        add('logs-clickhouse', 'http', '127.0.0.1', 8123, '/ping')
        add('logs-vector', 'http', '127.0.0.1', 8686, '/health')
    return targets


def probe(target, connection_factory=None):
    result = {'name': target['name'],
              'url': '%s://%s:%s%s' % (target['scheme'], target['host'], target['port'],
                                       target['path'].split('?', 1)[0])}
    if target['configError']:
        result['status'] = target['configError']
        return result
    started = datetime.now(timezone.utc)
    try:
        if connection_factory:
            connection = connection_factory(target)
        elif target['scheme'] == 'https':
            # Local self-signed listeners (OpenVault): the peer is this host, so the certificate is
            # not verified; reported as such and never used for anything but status fields. Any
            # other peer would need a verified connection, so it is refused instead.
            if not ipaddress.ip_address(target['host']).is_loopback:
                raise ValueError('unverified TLS probe is limited to loopback listeners')
            context = ssl._create_unverified_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = http.client.HTTPSConnection(target['host'], target['port'], timeout=2, context=context)
        else:
            connection = http.client.HTTPConnection(target['host'], target['port'], timeout=2)
        try:
            connection.request('GET', target['path'], headers={'User-Agent': 'mns-diagnostics/' + DIAGNOSTICS_VERSION,
                                                               'Connection': 'close'})
            response = connection.getresponse()
            body = response.read(65537)
            result['httpStatus'] = response.status
            cache = response.getheader('Cache-Control')
            if cache and target['name'] == 'app':
                result['cacheControl'] = safe_scalar(cache[:120])
        finally:
            connection.close()
    except (OSError, http.client.HTTPException, ValueError):
        result['status'] = 'CONNECTION_FAILED'
        return result
    result['latencyMs'] = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    result['status'] = 'OK' if 200 <= result['httpStatus'] < 300 else 'HTTP_ERROR'
    fields = HEALTH_FIELDS.get(target['name'], ())
    if fields and len(body) <= 65536:
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            data = None
        if isinstance(data, dict):
            result['fields'] = {key: safe_scalar(data[key]) for key in fields if key in data
                                and not isinstance(data[key], (dict, list))}
    if target['scheme'] == 'https':
        result['tls'] = 'LOCAL_UNVERIFIED'
    return result


def health(drop=drop_privileges):
    configs = load_configs()
    try:
        webapps_env = parse_env(trusted_read(WEBAPPS_ENV))
    except FileNotFoundError:
        webapps_env = None
    except (OSError, ValueError, UnicodeError):
        webapps_env = 'UNREADABLE_OR_UNSAFE'
    targets = health_targets(configs, webapps_env, APP_ROOT.is_dir())
    drop()
    return {'targets': [probe(target) for target in targets],
            'scope': 'FIXED_LOCAL_HEALTH_ENDPOINTS_ONLY_GET_NO_CREDENTIALS'}


# agent: job outcomes of the Agent journal, keeping only listed fields of its structured log lines.
AGENT_LINE = re.compile(r'\[mnscloud-agent\] (\d{4}-\d\d-\d\dT[\d:.]+Z) (.+?)(?: (\{.*\}))?')
AGENT_FIELDS = ('jobUUID', 'jobType', 'product', 'targetRef', 'targetVersion', 'scheduled', 'status', 'stage',
                'step', 'code', 'durationMs', 'revision', 'releaseTag', 'scope', 'error', 'rssBytes',
                'heapUsedBytes', 'uptimeSeconds', 'jobPolling')
AGENT_EVENTS = 60


def agent_events(text):
    events, resource, started, levels = [], None, None, Counter()
    for raw in text.splitlines():
        row = json.loads(raw)
        message = row.get('MESSAGE', '')
        if not isinstance(message, str):
            continue
        match = AGENT_LINE.fullmatch(message.strip())
        if not match:
            continue
        when, text_part, extra = match.groups()
        level = {'3': 'error', '4': 'warn'}.get(str(row.get('PRIORITY', '')), 'info')
        fields = {}
        if extra:
            try:
                data = json.loads(extra)
            except ValueError:
                data = None
            if isinstance(data, dict):
                for key in AGENT_FIELDS:
                    value = data.get(key)
                    if value is None or isinstance(value, (dict, list)):
                        continue
                    fields[key] = mask_line(str(value))[:300] if key == 'error' else safe_scalar(value)
        message_text = mask_line(text_part)[:160]
        levels[level] += 1
        if message_text == 'Agent resource usage.':
            resource = {'at': when, **fields}
            continue
        if message_text == 'Agent started.':
            started = when
        events.append({'at': when, 'level': level, 'message': message_text, **fields})
    return {'started': started, 'resource': resource, 'levels24h': dict(levels), 'events': events[-AGENT_EVENTS:]}


def agent():
    output = {'agent': build_metadata(AGENT_INSTALL) if AGENT_INSTALL.is_dir() else 'NOT_INSTALLED'}
    try:
        output['service'] = dict(line.split('=', 1) for line in run(
            ['/usr/bin/systemctl', '--no-pager', 'show', '--property=ActiveState,SubState,NRestarts,'
             'ActiveEnterTimestamp', 'mnscloud-agent.service'], limit=4096).splitlines() if '=' in line)
        output['service'] = {key: safe_scalar(value) for key, value in output['service'].items()}
    except (OSError, ValueError, subprocess.SubprocessError):
        output['service'] = 'UNAVAILABLE'
    try:
        text = run(['/usr/bin/journalctl', '--no-pager', '--output=json', '--output-fields=MESSAGE,PRIORITY',
                    '--since=-24h', '--lines=20000', '--unit=mnscloud-agent.service'],
                   limit=JOURNAL_OUTPUT_BYTES * 2, timeout=30)
        output.update(agent_events(text))
    except ValueError:
        output['events'] = 'OUTPUT_TOO_LARGE'
    except (OSError, subprocess.SubprocessError):
        output['events'] = 'UNAVAILABLE'
    output['masking'] = 'LISTED_FIELDS_ONLY_ERRORS_MASKED'
    return output


def os_release(path=Path('/usr/lib/os-release')):  # /etc/os-release is a symlink to it
    values = {}
    try:
        for line in public_read(path, 16384).decode('utf-8', errors='replace').splitlines():
            key, sep, value = line.partition('=')
            if sep and key in ('PRETTY_NAME', 'VERSION_ID', 'ID'):
                values[key] = safe_scalar(value.strip().strip('"'))
    except (OSError, ValueError):
        pass
    return values


def host():
    uname = os.uname()
    output = {'hostname': safe_scalar(socket.gethostname()), 'os': os_release(),
              'kernel': safe_scalar(uname.release), 'arch': safe_scalar(uname.machine), 'cpus': os.cpu_count()}
    try:
        for line in public_read(Path('/proc/stat'), 1048576).decode().splitlines():
            if line.startswith('btime '):
                output['bootedAt'] = datetime.fromtimestamp(int(line.split()[1]), timezone.utc).isoformat()
    except (OSError, ValueError):
        pass
    for key, args in (('virtualization', ['/usr/bin/systemd-detect-virt']),
                      ('ntpSynchronized', ['/usr/bin/timedatectl', 'show', '-p', 'NTPSynchronized', '--value']),
                      ('timezone', ['/usr/bin/timedatectl', 'show', '-p', 'Timezone', '--value'])):
        try:
            output[key] = safe_scalar(run(args, limit=256, timeout=5).strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            output[key] = 'UNAVAILABLE'
    return output


def parse_listeners(text):
    listeners = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ('tcp', 'udp'):
            continue
        local = parts[4]
        address, _, port = local.rpartition(':')
        if port.isdecimal() and re.fullmatch(r'[][0-9A-Za-z.:*%]{1,64}', address):
            listeners.append({'proto': parts[0], 'address': address, 'port': int(port)})
    return sorted(listeners, key=lambda item: (item['proto'], item['port'], item['address']))[:200]


def network():
    output = {}
    try:
        interfaces = []
        for item in json.loads(run(['/usr/sbin/ip', '-j', 'addr', 'show'], limit=1048576)):
            interfaces.append({'name': safe_scalar(item.get('ifname')), 'state': safe_scalar(item.get('operstate')),
                               'addresses': [{'address': safe_scalar(a.get('local')),
                                              'prefix': safe_scalar(a.get('prefixlen')),
                                              'family': safe_scalar(a.get('family')),
                                              'scope': safe_scalar(a.get('scope'))}
                                             for a in item.get('addr_info', [])[:16]]})
        output['interfaces'] = interfaces[:32]
    except (OSError, ValueError, subprocess.SubprocessError, TypeError):
        output['interfaces'] = 'UNAVAILABLE'
    routes = []
    for family in ('-4', '-6'):
        try:
            for item in json.loads(run(['/usr/sbin/ip', '-j', family, 'route', 'show', 'default'], limit=65536)):
                routes.append({'family': family[1:], 'dev': safe_scalar(item.get('dev')),
                               'gateway': safe_scalar(item.get('gateway'))})
        except (OSError, ValueError, subprocess.SubprocessError, TypeError):
            pass
    output['defaultRoutes'] = routes
    try:
        output['listeners'] = parse_listeners(run(['/usr/bin/ss', '-H', '-l', '-n', '-t', '-u'], limit=1048576))
    except (OSError, ValueError, subprocess.SubprocessError):
        output['listeners'] = 'UNAVAILABLE'
    try:
        output['nameservers'] = [safe_scalar(line.split()[1]) for line in public_read(
            Path('/etc/resolv.conf'), 16384).decode().splitlines() if line.startswith('nameserver ')][:8]
    except (OSError, ValueError, IndexError):
        output['nameservers'] = 'UNAVAILABLE'
    output['scope'] = 'ADDRESSES_ROUTES_LISTENING_PORTS_NO_PROCESSES_OR_PEERS'
    return output


TIMER_NAME = re.compile(r'(?:mnscloud-[a-z0-9-]{1,80}|snap\.certbot\.renew|certbot)\.timer')


def micros_iso(value):
    return (datetime.fromtimestamp(value / 1e6, timezone.utc).isoformat()
            if isinstance(value, int) and 0 < value < 2 ** 62 else None)


def timers():
    try:
        rows = json.loads(run(['/usr/bin/systemctl', '--no-pager', '--all', '--output=json', 'list-timers'],
                              limit=1048576))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'timers': 'UNAVAILABLE'}
    output = []
    for row in rows if isinstance(rows, list) else []:
        unit, service = row.get('unit', ''), row.get('activates', '')
        if not TIMER_NAME.fullmatch(unit) or not re.fullmatch(r'[A-Za-z0-9.@_-]{1,120}\.service', service):
            continue
        item = {'timer': unit, 'service': service, 'next': micros_iso(row.get('next')),
                'last': micros_iso(row.get('last'))}
        try:
            item.update({key: safe_scalar(value) for key, value in (line.split('=', 1) for line in run(
                ['/usr/bin/systemctl', '--no-pager', 'show', '--property=Result,ExecMainStatus,'
                 'ExecMainExitTimestamp,ActiveState', service], limit=4096).splitlines() if '=' in line)})
        except (OSError, ValueError, subprocess.SubprocessError):
            item['Result'] = 'UNAVAILABLE'
        output.append(item)
    return {'timers': output[:64]}


EDGE_VHOST_DIRS = (Path('/etc/nginx/mnscloud/theme-domains'), Path('/etc/nginx/mnscloud/runtime'),
                   Path('/etc/nginx/sites-enabled'), Path('/etc/nginx/conf.d'))
LETSENCRYPT_LIVE = Path('/etc/letsencrypt/live')
NGINX_CONFIGS = (('system', ['/usr/sbin/nginx', '-t']),
                 ('webapps', ['/usr/sbin/nginx', '-t', '-p', '/opt/mnscloud/webapps/runtime',
                              '-c', '/opt/mnscloud/webapps/runtime/nginx.conf']))


def run_result(args, timeout=15):
    """Exit code plus masked, bounded stderr of a fixed command."""
    import tempfile
    with tempfile.TemporaryFile() as errors:
        completed = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=errors, env=ENV, timeout=timeout)
        errors.seek(0)
        text = errors.read(16384).decode('utf-8', errors='replace')
    return completed.returncode, [mask_line(line) for line in text.splitlines()[-20:]]


def certificate(path):
    text = run(['/usr/bin/openssl', 'x509', '-noout', '-enddate', '-subject', '-ext', 'subjectAltName',
                '-in', str(path)], limit=65536, timeout=5)
    result = {}
    end = re.search(r'notAfter=(.+)', text)
    if end:
        expires = datetime.strptime(end.group(1).strip(), '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        result['notAfter'] = expires.isoformat()
        result['daysLeft'] = (expires - datetime.now(timezone.utc)).days
    subject = re.search(r'CN\s*=\s*([^,\n]+)', text)
    result['subject'] = safe_scalar(subject.group(1).strip()) if subject else None
    result['names'] = [safe_scalar(name) for name in re.findall(r'DNS:([A-Za-z0-9*.-]{1,253})', text)][:20]
    return result


def edge():
    output = {'nginx': {}, 'vhosts': {}, 'certificates': {}}
    for name, args in NGINX_CONFIGS:
        if not Path(args[0]).exists() or (name == 'webapps' and not Path(args[-1]).exists()):
            continue
        try:
            code, lines = run_result(args)
            output['nginx'][name] = {'configTest': 'OK' if code == 0 else 'FAILED', 'messages': lines}
        except (OSError, subprocess.SubprocessError):
            output['nginx'][name] = 'UNAVAILABLE'
    for directory in EDGE_VHOST_DIRS:
        if directory.is_dir() and not directory.is_symlink():
            names = sorted(entry.name for entry in directory.iterdir()
                           if re.fullmatch(r'[A-Za-z0-9._-]{1,120}', entry.name))
            output['vhosts'][str(directory)] = {'count': len(names), 'names': names[:300]}
    if LETSENCRYPT_LIVE.is_dir() and not LETSENCRYPT_LIVE.is_symlink():
        for entry in sorted(LETSENCRYPT_LIVE.iterdir())[:100]:
            if not entry.is_dir() or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', entry.name):
                continue
            try:
                output['certificates'][entry.name] = certificate(entry / 'fullchain.pem')
            except (OSError, ValueError, subprocess.SubprocessError):
                output['certificates'][entry.name] = 'UNREADABLE'
    output['scope'] = 'CONFIG_TEST_VHOST_FILE_NAMES_CERTIFICATE_EXPIRY_NO_CONFIG_CONTENT'
    return output


# access-summary: aggregate counts of the edge access log; no client addresses, users, queries or agents.
ACCESS_LOG = Path('/var/log/nginx/access.log')
ACCESS_TAIL_BYTES = 33554432
ACCESS_DEFAULT_MINUTES = 15
ACCESS_TOP = 200
ACCESS_LINE = re.compile(r'\S+ \S+ \S+ \[([^\]]{20,40})\] "([A-Z]{1,12}) (\S{1,4096})(?: [^"]{0,32})?" (\d{3}) ')
ID_SEGMENT = re.compile(r'\d+|[0-9a-fA-F-]{12,}|(?=\S*\d)[A-Za-z0-9_-]{16,}')
WORD_SEGMENT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,40}')


def parse_access_request(text):
    if text.endswith('\n'):
        text = text[:-1]
    if not text:
        return ACCESS_DEFAULT_MINUTES
    if len(text) > 4 or not text.isdecimal() or not 1 <= int(text) <= JOURNAL_MAX_MINUTES:
        raise PermissionError('Unsupported access-summary window')
    return int(text)


def normalize_path(path):
    path = path.split('?', 1)[0].split('#', 1)[0]
    segments = [segment for segment in path.split('/') if segment][:8]
    output = []
    for segment in segments:
        if ID_SEGMENT.fullmatch(segment):
            output.append(':id')
        elif WORD_SEGMENT.fullmatch(segment):
            output.append(segment)
        else:
            output.append(':value')  # domains, e-mails, encoded or file names
    suffix = '/...' if len([s for s in path.split('/') if s]) > 8 else ''
    return ('/' + '/'.join(output) + suffix)[:200]


def access_summary(minutes, path=ACCESS_LOG, now=None):
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(minutes=minutes)
    try:
        for parent in reversed(path.parents):
            if stat.S_ISLNK(parent.lstat().st_mode):
                raise ValueError('Symlinked log directory')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Unsupported log file type')
            stream.seek(max(0, info.st_size - ACCESS_TAIL_BYTES))
            data = stream.read(ACCESS_TAIL_BYTES)
    except FileNotFoundError:
        return {'status': 'NO_ACCESS_LOG'}
    except (OSError, ValueError):
        return {'status': 'UNREADABLE_OR_UNSAFE'}
    lines = data.decode('utf-8', errors='replace').splitlines()
    if info.st_size > ACCESS_TAIL_BYTES and lines:
        lines = lines[1:]
    counts, classes, earliest, total = Counter(), Counter(), None, 0
    for line in lines:
        match = ACCESS_LINE.match(line)
        if not match:
            continue
        try:
            when = datetime.strptime(match.group(1), '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            continue
        earliest = when if earliest is None or when < earliest else earliest
        if when < start or when > now + timedelta(minutes=5):
            continue
        method, status = match.group(2), match.group(4)
        counts[(method, normalize_path(match.group(3)), status)] += 1
        classes[status[0] + 'xx'] += 1
        total += 1
    return {'status': 'OK', 'sinceMinutes': minutes, 'total': total, 'byStatusClass': dict(classes),
            'windowComplete': earliest is not None and earliest <= start,
            'oldestLineAt': earliest.isoformat() if earliest else None,
            'top': [{'method': key[0], 'path': key[1], 'status': int(key[2]), 'count': value}
                    for key, value in counts.most_common(ACCESS_TOP)],
            'scope': 'COUNTS_BY_METHOD_NORMALIZED_PATH_STATUS_NO_CLIENTS_QUERIES_OR_AGENTS'}


LOG_USAGE_DIRS = ('/var/log', '/var/log/journal', '/var/log/nginx', '/var/log/asterisk', '/var/log/freeswitch',
                  '/var/log/mnscloud', '/var/log/freeradius', '/var/lib/mnscloud/files', '/var/lib/clickhouse')


def largest_logs(root=Path('/var/log'), limit=10, budget=5000):
    found, seen = [], 0
    for directory, folders, files in os.walk(root, followlinks=False):
        folders[:] = [name for name in folders if directory.count('/') < 5]
        for name in files:
            seen += 1
            if seen > budget:
                break
            try:
                info = os.lstat(os.path.join(directory, name))
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                found.append((info.st_size, os.path.join(directory, name)))
    found.sort(reverse=True)
    return [{'path': safe_scalar(path), 'bytes': size} for size, path in found[:limit]]


def log_usage():
    output = {'directories': {}}
    for directory in LOG_USAGE_DIRS:
        if not os.path.isdir(directory) or os.path.islink(directory):
            continue
        try:
            value = run(['/usr/bin/du', '-s', '-b', '-x', directory], limit=4096, timeout=8).split()[0]
            output['directories'][directory] = int(value)
        except (OSError, ValueError, IndexError, subprocess.SubprocessError):
            output['directories'][directory] = 'UNAVAILABLE'
    try:
        text = run(['/usr/bin/journalctl', '--disk-usage'], limit=4096, timeout=8)
        match = re.search(r'take up ([0-9.]+[KMGT]?B?)', text)
        output['journalDiskUsage'] = match.group(1) if match else 'UNKNOWN'
    except (OSError, ValueError, subprocess.SubprocessError):
        output['journalDiskUsage'] = 'UNAVAILABLE'
    output['largestLogFiles'] = largest_logs()
    return output


STAT_NAME = re.compile(r'[a-z_]{1,32}:[a-z0-9_]{1,64}')


def numeric_stats(text):
    stats = {}
    for name, value in re.findall(r'([a-z_]{1,32}:[a-z0-9_]{1,64})\s*=\s*(-?\d{1,15})', text):
        stats[name] = int(value)
    return dict(list(stats.items())[:120])


def first_int(pattern, text):
    match = re.search(pattern, text)
    return int(match.group(1)) if match else None


VOIP_TOOLS = {
    'kamailio': '/usr/sbin/kamcmd',
    'opensips': '/usr/bin/opensips-cli',
    'asterisk': '/usr/sbin/asterisk',
    'freeswitch': '/usr/bin/fs_cli',
    'rtpengine': '/usr/bin/rtpengine-ctl',
}


def voip_summary(runner=None):
    """Registration/call/session counters of the local engines; numbers only, never users or numbers."""
    runner = runner or (lambda args: run(args, limit=262144, timeout=6))
    output = {}

    def collect(name, function):
        if not os.path.exists(VOIP_TOOLS[name]):
            return
        try:
            output[name] = function()
        except (OSError, ValueError, subprocess.SubprocessError):
            output[name] = 'UNAVAILABLE'

    collect('kamailio', lambda: numeric_stats(runner([VOIP_TOOLS['kamailio'], 'stats.get_statistics', 'usrloc:',
                                                      'dialog:', 'tm:', 'core:rcv_requests', 'core:drop_requests',
                                                      'core:err_requests', 'core:bad_msg_hdr'])))

    def opensips():
        data = json.loads(runner([VOIP_TOOLS['opensips'], '-x', 'mi', 'get_statistics', 'usrloc:', 'dialog:',
                                  'tm:', 'core:rcv_requests', 'core:drop_requests', 'core:err_requests',
                                  'core:bad_msg_hdr']))
        return {key: value for key, value in data.items()
                if STAT_NAME.fullmatch(key) and isinstance(value, int)} if isinstance(data, dict) else {}
    collect('opensips', opensips)

    def asterisk():
        channels = runner([VOIP_TOOLS['asterisk'], '-rx', 'core show channels count'])
        return {'activeChannels': first_int(r'(\d+) active channels?', channels),
                'activeCalls': first_int(r'(\d+) active calls?', channels),
                'callsProcessed': first_int(r'(\d+) calls? processed', channels),
                'pjsipContacts': first_int(r'Objects found: (\d+)',
                                           runner([VOIP_TOOLS['asterisk'], '-rx', 'pjsip show contacts'])) or 0,
                'pjsipEndpoints': first_int(r'Objects found: (\d+)',
                                            runner([VOIP_TOOLS['asterisk'], '-rx', 'pjsip show endpoints'])) or 0,
                'pjsipRegistrations': first_int(r'Objects found: (\d+)',
                                                runner([VOIP_TOOLS['asterisk'], '-rx', 'pjsip show registrations'])) or 0}
    collect('asterisk', asterisk)

    def freeswitch():
        return {'registrations': first_int(r'(\d+) total', runner([VOIP_TOOLS['freeswitch'], '-x',
                                                                    'show registrations count'])),
                'calls': first_int(r'(\d+) total', runner([VOIP_TOOLS['freeswitch'], '-x', 'show calls count'])),
                'channels': first_int(r'(\d+) total', runner([VOIP_TOOLS['freeswitch'], '-x', 'show channels count'])),
                'sofiaProfiles': first_int(r'(\d+) profiles?', runner([VOIP_TOOLS['freeswitch'], '-x', 'sofia status']))}
    collect('freeswitch', freeswitch)

    def rtpengine():
        text = runner([VOIP_TOOLS['rtpengine'], '-ip', '127.0.0.1:2224', 'list', 'numsessions'])
        return {'sessionsTotal': first_int(r'Current sessions total: (\d+)', text),
                'sessionsOwn': first_int(r'Current sessions own: (\d+)', text),
                'transcoded': first_int(r'Current transcoded media: (\d+)', text)}
    collect('rtpengine', rtpengine)
    output['scope'] = 'COUNTERS_ONLY_NO_USERS_NUMBERS_OR_ADDRESSES'
    return output


# schema-status: the diagnostics account authenticates to the local MariaDB through unix_socket (no
# password exists) and holds SELECT on the columns below only (diagnostics/db_account.py).
DB_ENV = CONFIG_DIR / 'db.env'
SCHEMA_REVISION_SQL = ('SELECT SarClusterKey, SarDbReleaseTag, SarAppliedAt FROM SchemaAppliedRevision '
                       'WHERE SarStatus = 1 AND SarDateDeleted IS NULL ORDER BY SarAppliedAt DESC LIMIT 5')
SCHEMA_JOBS_SQL = ('SELECT SrjStage, SrjDbReleaseTag, SrjStatus, SrjStartedAt, SrjFinishedAt, SrjLastErrorCode, '
                   'SrjDateCreated FROM SchemaReconcileJob WHERE SrjDateDeleted IS NULL '
                   'ORDER BY SrjDateCreated DESC LIMIT 10')


def schema_rows(text, names):
    rows = []
    for line in text.splitlines():
        values = line.split('\t')
        if len(values) == len(names):
            rows.append({name: (None if value == 'NULL' else safe_scalar(value)) for name, value in zip(names, values)})
    return rows


def schema_status(drop=drop_privileges, runner=None):
    try:
        database = parse_env(trusted_read(DB_ENV)).get('DB_NAME', '')
    except FileNotFoundError:
        return {'status': 'NOT_A_DATABASE_HOST'}
    except (OSError, ValueError, UnicodeError):
        return {'status': 'UNREADABLE_OR_UNSAFE'}
    if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', database):
        return {'status': 'INVALID_DB_NAME'}
    drop()
    runner = runner or (lambda sql: run(['/usr/bin/mariadb', '--protocol=socket', '-u', DIAGNOSTICS_USER, '-N',
                                         '--batch', '--raw', database, '-e', sql], limit=65536, timeout=10))
    try:
        revisions = schema_rows(runner(SCHEMA_REVISION_SQL), ('cluster', 'releaseTag', 'appliedAt'))
        jobs = schema_rows(runner(SCHEMA_JOBS_SQL), ('stage', 'releaseTag', 'status', 'startedAt', 'finishedAt',
                                                      'errorCode', 'createdAt'))
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'status': 'DIAGNOSTICS_DB_ACCOUNT_UNAVAILABLE', 'database': database}
    return {'status': 'OK', 'database': database, 'appliedRevisions': revisions, 'reconcileJobs': jobs,
            'scope': 'SCHEMA_REVISION_AND_RECONCILE_JOB_COLUMNS_ONLY'}


# Historical log queries use fixed sources and resumable, bounded pages. The request is data,
# never a command. Cursors identify a source snapshot; they confer no additional authority.
QUERY_SCAN_BYTES = 8 * 1024 * 1024
QUERY_LINE_BYTES = 65536
QUERY_PAGE_BYTES = 1024 * 1024
QUERY_SECONDS = 20
ROTATION_SUFFIX = re.compile(r'(?:-[0-9]{8}-[0-9]{6}|\.[0-9]{1,14}|[-.][0-9]{4}-[0-9]{2}-[0-9]{2}(?:[-.][0-9]{2}[-.][0-9]{2}[-.][0-9]{2})?)(?:\.gz)?')
QUERY_TIMESTAMP = re.compile(r'(?<!\d)(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)')


def query_encode(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).decode().rstrip('=')


def query_decode(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,8192}', value):
        raise PermissionError('Invalid query encoding')
    try:
        result = json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
    except (ValueError, UnicodeError):
        raise PermissionError('Invalid query JSON') from None
    if not isinstance(result, dict):
        raise PermissionError('Invalid query object')
    return result


def query_date(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})', value):
        raise PermissionError('An explicit timestamp offset is required')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise PermissionError('Invalid date') from None


def parse_log_query(text):
    if len(text) > 8193:
        raise PermissionError('Query too large')
    q = query_decode(text.removesuffix('\n'))
    if q == {'list': True}:
        return q
    if set(q) - {'source', 'rotation', 'since', 'until', 'utcOffset', 'contains', 'limit', 'cursor'}:
        raise PermissionError('Unknown query field')
    source = q.get('source')
    if not isinstance(source, str):
        raise PermissionError('Source required')
    if source.startswith('journal:'):
        unit = source[8:]
        if unit not in UNITS and not MNSCLOUD_UNIT.fullmatch(unit):
            raise PermissionError('Unsupported unit')
        if q.get('rotation'):
            raise PermissionError('Journal has no file rotation selector')
    elif source not in LOG_FILES:
        raise PermissionError('Unsupported source')
    rotation = q.get('rotation', '')
    if not isinstance(rotation, str) or (rotation and not ROTATION_SUFFIX.fullmatch(rotation)):
        raise PermissionError('Unsupported rotation')
    since, until = query_date(q.get('since')), query_date(q.get('until'))
    if since > until:
        raise PermissionError('Reversed interval')
    offset = q.get('utcOffset', '+00:00')
    if not isinstance(offset, str) or not re.fullmatch(r'[+-](?:0\d|1[0-4]):[0-5]\d', offset):
        raise PermissionError('Invalid file timestamp offset')
    contains = q.get('contains', '')
    if not isinstance(contains, str) or len(contains) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in contains):
        raise PermissionError('Invalid literal filter')
    limit = q.get('limit', 200)
    if type(limit) is not int or not 1 <= limit <= 500:
        raise PermissionError('Invalid page size')
    if 'cursor' in q:
        query_decode(q['cursor'])
    return q


def query_mask(text, source):
    # Redact before matching too: filtering must not become a secret-value oracle.
    if source in USER_MASKED_LOGS:
        text = BRACKETED.sub('[USER]', text)
    text = CONTROL.sub('', text)
    for pattern, replacement in MASKS:
        text = pattern.sub(replacement, text)
    # Standalone PEM/base64 continuation lines can occur without a key header on this page.
    text = re.sub(r'(?m)^\s*[A-Za-z0-9+/=]{32,}\s*$', REDACTED, text)
    return text


def query_matches(text, q, stamp):
    return (stamp is not None and query_date(q['since']) <= stamp <= query_date(q['until'])
            and q.get('contains', '').casefold() in text.casefold())


def query_binding(q):
    return hashlib.sha256(json.dumps({k: v for k, v in q.items() if k != 'cursor'}, sort_keys=True).encode()).hexdigest()


def query_open(path):
    # Walk using directory descriptors: no parent symlink swap can escape the allowlist.
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            new_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new_fd
        result = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    info = os.fstat(result)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(result)
        raise ValueError('Unsafe log')
    return os.fdopen(result, 'rb')


def query_file(q):
    path = LOG_FILES[q['source']]
    path = path.with_name(path.name + q.get('rotation', ''))
    result = {'source': q['source'], 'lines': [], 'nextCursor': None, 'complete': False,
              'scannedBytes': 0, 'unparsedLines': 0, 'status': 'OK'}
    cursor = query_decode(q['cursor']) if q.get('cursor') else {}
    binding = query_binding(q)
    if cursor and cursor.get('query') != binding:
        raise PermissionError('Cursor belongs to another query')
    started = time.monotonic()
    with query_open(path) as raw:
        info = os.fstat(raw.fileno())
        identity = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
        # Fail explicitly on rotation, truncation or append; never silently skip a changed source.
        if cursor and cursor.get('identity') != identity:
            return dict(result, status='SOURCE_CHANGED')
        offset = cursor.get('offset', 0)
        if type(offset) is not int or offset < 0 or offset > 2**63 - 1:
            raise PermissionError('Invalid cursor offset')
        compressed = q.get('rotation', '').endswith('.gz')
        stream = gzip.GzipFile(fileobj=raw) if compressed else raw
        try:
            # Gzip seek replays decompression with a deadline; it never allocates the whole file.
            skipped = 0
            if compressed:
                while skipped < offset:
                    if time.monotonic() - started > QUERY_SECONDS:
                        return dict(result, status='COMPRESSED_SEEK_BUDGET_EXCEEDED')
                    chunk = stream.read(min(65536, offset - skipped))
                    if not chunk:
                        raise PermissionError('Cursor beyond file')
                    skipped += len(chunk)
                if offset and chunk[-1:] != b'\n':
                    raise PermissionError('Cursor must start at a line boundary')
            elif offset:
                stream.seek(offset - 1)
                if stream.read(1) != b'\n':
                    raise PermissionError('Cursor must start at a line boundary')
            previous = cursor.get('stamp')
            stamp = datetime.fromisoformat(previous) if isinstance(previous, str) else None
            if stamp is not None and stamp.tzinfo is None:
                raise PermissionError('Invalid cursor timestamp')
            output_bytes = 0
            while result['scannedBytes'] < QUERY_SCAN_BYTES and time.monotonic() - started < QUERY_SECONDS:
                position = stream.tell()
                line = stream.readline(QUERY_LINE_BYTES + 1)
                if not line:
                    result['complete'] = True
                    break
                if len(line) > QUERY_LINE_BYTES:
                    return dict(result, status='LINE_TOO_LARGE')
                result['scannedBytes'] += len(line)
                text = line.decode('utf-8', errors='replace').rstrip('\r\n')
                match = QUERY_TIMESTAMP.search(text)
                if match:
                    try:
                        stamp = datetime.fromisoformat(match[1].replace('Z', '+00:00'))
                        if stamp.tzinfo is None:
                            zone = datetime.fromisoformat('2000-01-01T00:00:00' + q.get('utcOffset', '+00:00')).tzinfo
                            stamp = stamp.replace(tzinfo=zone)
                    except ValueError:
                        stamp = None
                if stamp is None:
                    result['unparsedLines'] += 1
                text = query_mask(text, q['source'])
                if query_matches(text, q, stamp):
                    size = len(json.dumps(text).encode())
                    if output_bytes + size > QUERY_PAGE_BYTES:
                        stream.seek(position)
                        break
                    result['lines'].append(text)
                    output_bytes += size
                    if len(result['lines']) >= q.get('limit', 200):
                        break
            if not result['complete']:
                result['nextCursor'] = query_encode({'query': binding, 'identity': identity,
                    'offset': stream.tell(), 'stamp': stamp.isoformat() if stamp else None})
            if os.fstat(raw.fileno()).st_mtime_ns != identity[3]:
                result.update(status='SOURCE_CHANGED', complete=False, nextCursor=None)
        finally:
            if compressed:
                stream.close()
    return result


def query_journal(q):
    import select
    result = {'source': q['source'], 'lines': [], 'nextCursor': None, 'complete': False,
              'scannedBytes': 0, 'unparsedLines': 0, 'status': 'OK'}
    binding = query_binding(q)
    cursor = query_decode(q['cursor']) if q.get('cursor') else {}
    if cursor and cursor.get('query') != binding:
        raise PermissionError('Cursor belongs to another query')
    after = cursor.get('after')
    if after is not None and (not isinstance(after, str) or not re.fullmatch(r'[A-Za-z0-9;=_-]{1,512}', after)):
        raise PermissionError('Invalid journal cursor')
    args = ['/usr/bin/journalctl', '--no-pager', '--output=json', '--all',
            '--unit=' + q['source'][8:] + '.service',
            '--until=' + query_date(q['until']).astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')]
    if after:
        args.append('--after-cursor=' + after)
    else:
        args.append('--since=' + query_date(q['since']).astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
    started = time.monotonic()
    output_bytes = 0
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV) as process:
        try:
            pending = b''
            while result['scannedBytes'] < QUERY_SCAN_BYTES and time.monotonic() - started < QUERY_SECONDS:
                if b'\n' not in pending:
                    if not select.select([process.stdout], [], [], .2)[0]:
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        result['complete'] = process.wait(timeout=2) == 0 and not pending
                        if not result['complete']:
                            result['status'] = 'JOURNAL_UNAVAILABLE'
                        break
                    pending += chunk
                    if len(pending) > QUERY_LINE_BYTES and b'\n' not in pending:
                        result['status'] = 'LINE_TOO_LARGE'
                        break
                    continue
                line, pending = pending.split(b'\n', 1)
                if len(line) > QUERY_LINE_BYTES:
                    result['status'] = 'LINE_TOO_LARGE'
                    break
                row = json.loads(line)
                stamp = datetime.fromtimestamp(int(row['__REALTIME_TIMESTAMP']) / 1e6, timezone.utc)
                message = row.get('MESSAGE', '')
                text = query_mask(message if isinstance(message, str) else '[NON_TEXT_MESSAGE]', q['source'])
                text = stamp.isoformat() + ' ' + str(row.get('PRIORITY', '-')) + ' ' + text
                if query_matches(text, q, stamp):
                    size = len(json.dumps(text).encode())
                    if output_bytes + size > QUERY_PAGE_BYTES:
                        break
                    result['lines'].append(text)
                    output_bytes += size
                after = row['__CURSOR']
                result['scannedBytes'] += len(line) + 1
                if len(result['lines']) >= q.get('limit', 200):
                    break
            if not result['complete'] and after and result['status'] == 'OK':
                result['nextCursor'] = query_encode({'query': binding, 'after': after})
            elif not result['complete'] and result['status'] == 'OK':
                result['status'] = 'QUERY_BUDGET_EXCEEDED'
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
    return result


def serialized_log_query(q):
    import fcntl
    fd = os.open('/run/mns-diagnostics-log-query.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'rb+') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError('Unsafe query lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'status': 'BUSY', 'complete': False, 'nextCursor': None, 'lines': []}
        return log_query(q)


def log_query(q):
    if q.get('list'):
        sources = []
        for name, path in LOG_FILES.items():
            rotations = []
            try:
                for index, item in enumerate(path.parent.iterdir()):
                    if index >= 10000:
                        raise ValueError('Log directory enumeration budget exceeded')
                    suffix = item.name.removeprefix(path.name)
                    if item.name.startswith(path.name) and (not suffix or ROTATION_SUFFIX.fullmatch(suffix)):
                        with query_open(item):
                            rotations.append(suffix)
                    if len(rotations) > 1000:
                        raise ValueError('Too many rotations')
            except FileNotFoundError:
                pass
            sources.append({'source': name, 'rotations': sorted(rotations)})
        return {'sources': sources, 'journalUnits': sorted(set(UNITS) | set(installed_units())),
                'status': 'OK'}
    try:
        result = query_journal(q) if q['source'].startswith('journal:') else query_file(q)
    except FileNotFoundError:
        result = {'status': 'SOURCE_MISSING', 'complete': False, 'nextCursor': None, 'lines': []}
    except (ValueError, OSError, EOFError):
        result = {'status': 'SOURCE_UNAVAILABLE_OR_UNSAFE', 'complete': False, 'nextCursor': None, 'lines': []}
    result['masking'] = 'SECRETS_TOKENS_AND_KEYS_REDACTED_BEST_EFFORT'
    return result


# Audio metadata only: no directory listings, content, checksums or caller-selected roots.
AUDIO_ROOTS = {
    'files': Path('/var/lib/mnscloud/files'),
    'freeswitch': Path('/var/lib/freeswitch/recordings'),
    'asterisk': Path('/var/spool/asterisk/monitor'),
}
AUDIO_EXTENSION = re.compile(r'.+\.(?:wav|mp3|ogg|flac|gsm|ulaw|alaw|sln|sln16|opus)$', re.I)


def parse_audio_stat(text):
    if len(text) > 8193:
        raise PermissionError('Query too large')
    q = query_decode(text.removesuffix('\n'))
    if (set(q) != {'source', 'relativePath'} or not isinstance(q.get('source'), str)
            or q['source'] not in AUDIO_ROOTS):
        raise PermissionError('Unsupported audio source')
    relative = q.get('relativePath')
    if (not isinstance(relative, str) or len(relative) > 1024
            or not re.fullmatch(r'[A-Za-z0-9_./-]+', relative)
            or len(relative.split('/')) > 16
            or any(part in ('', '.', '..') for part in relative.split('/'))
            or not AUDIO_EXTENSION.fullmatch(relative)):
        raise PermissionError('Unsupported audio path')
    if q['source'] == 'files' and not re.fullmatch(
            r'tenants/(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12})/'
            r'voip-pabx/(?:recordings|media-files)/audio/'
            r'[0-9]{4}/[0-9]{2}/(?:[0-9]{2}/)?[A-Za-z0-9_-]+(?:-v[0-9]+)?\.[A-Za-z0-9]+', relative):
        raise PermissionError('Unsupported canonical audio path')
    return q


def audio_stat(q):
    # Revalidate at the operation boundary too. query_open walks every directory with
    # O_NOFOLLOW and rejects final symlinks, hard links and special files before fstat.
    q = parse_audio_stat(query_encode(q))
    result = {'source': q['source'], 'exists': None}
    try:
        with query_open(AUDIO_ROOTS[q['source']] / q['relativePath']) as audio:
            info = os.fstat(audio.fileno())
        result.update(status='OK', exists=True, sizeBytes=info.st_size,
                      modifiedAt=datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat())
    except FileNotFoundError:
        result.update(status='AUDIO_MISSING', exists=False)
    except (ValueError, OSError):
        result.update(status='AUDIO_UNAVAILABLE_OR_UNSAFE')
    return result


# Operations: (handler, reads stdin parameters, drop privileges before any work).
OPERATIONS = {
    'config': ('config', False, False),
    'config-check': ('config-check', False, False),
    'logs': ('logs', False, False),
    'logs-text': ('logs-text', False, False),
    'journal': ('journal', True, False),
    'log-query': ('log-query', True, False),
    'audio-stat': ('audio-stat', True, False),
    'container-logs': ('container-logs', True, False),
    'versions': ('versions', False, False),
    'connectivity': ('connectivity', False, False),
    'asterisk-odbc': ('asterisk-odbc', False, False),
    'artifacts': ('artifacts', False, True),
    'health': ('health', False, False),
    'agent': ('agent', False, False),
    'host': ('host', False, True),
    'network': ('network', False, True),
    'timers': ('timers', False, True),
    'edge': ('edge', False, False),
    'access-summary': ('access-summary', True, False),
    'log-usage': ('log-usage', False, False),
    'voip-summary': ('voip-summary', False, False),
    'schema-status': ('schema-status', False, False),
}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in OPERATIONS:
        print('DENIED: Unsupported collector operation.', file=sys.stderr)
        return 126
    operation = sys.argv[1]
    _, takes_input, drop_first = OPERATIONS[operation]
    signal.alarm(40)
    request = None
    if takes_input:
        try:
            request = sys.stdin.buffer.read((8192 if operation in ('log-query', 'audio-stat') else JOURNAL_REQUEST_BYTES) + 2).decode('ascii')
            if operation == 'log-query':
                request = parse_log_query(request)
            elif operation == 'audio-stat':
                request = parse_audio_stat(request)
            elif operation == 'journal':
                parse_journal_request(request)
            elif operation == 'container-logs':
                parse_container_request(request)
            else:
                request = parse_access_request(request)
        except (PermissionError, UnicodeDecodeError, ValueError):
            usage = {'audio-stat': 'audio-stat BASE64URL_JSON', 'log-query': 'log-query BASE64URL_JSON', 'journal': 'journal UNIT [MINUTES] [PRIORITY]', 'container-logs': 'container-logs CONTAINER [MINUTES]'}.get(
                operation, 'access-summary [MINUTES]')
            print('DENIED: Unsupported ' + operation + ' request. Use: ' + usage + '.', file=sys.stderr)
            return 126
    if os.geteuid() != 0:
        print('ERROR: Collector requires its dedicated sudo rule.', file=sys.stderr)
        return 1
    os.umask(0o077)
    if drop_first:
        drop_privileges()
    if operation == 'log-query':
        result = serialized_log_query(request)
    elif operation == 'audio-stat':
        result = audio_stat(request)
    elif operation == 'journal':
        result = journal(request)
    elif operation == 'container-logs':
        result = container_logs(request)
    elif operation == 'access-summary':
        result = access_summary(request)
    elif operation in ('config', 'config-check', 'connectivity'):
        configs = load_configs()
        result = connectivity(configs) if operation == 'connectivity' else config_report(configs, operation == 'config-check')
    else:
        result = {'logs': logs, 'logs-text': logs_text, 'versions': versions, 'asterisk-odbc': asterisk_odbc,
                  'artifacts': artifacts, 'health': health, 'agent': agent, 'host': host, 'network': network,
                  'timers': timers, 'edge': edge, 'log-usage': log_usage, 'voip-summary': voip_summary,
                  'schema-status': schema_status}[operation]()
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        print('ERROR: Diagnostic collection failed; raw details suppressed.', file=sys.stderr)
        sys.exit(1)
