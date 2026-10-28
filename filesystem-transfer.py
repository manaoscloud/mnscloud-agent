#!/usr/bin/env python3
"""One leased audio transfer, outbound HTTPS only; credentials arrive on stdin."""
import http.client
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import sys
import time
import uuid
from urllib.parse import urlsplit

ROOTS = {
    'files': Path('/var/lib/mnscloud/files'),
    'freeswitch': Path('/var/lib/freeswitch/recordings'),
    'asterisk': Path('/var/spool/asterisk/monitor'),
}
UUID = r'(?:[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}|[a-fA-F0-9]{32})'
MAX_BYTES = 1024 ** 3
INVALID_RANGE = "Unsatisfiable byte range"


def target(source, relative):
    if source not in ROOTS or not isinstance(relative, str) or len(relative) > 1024:
        raise ValueError('Invalid audio source')
    if (not re.fullmatch(r'[A-Za-z0-9_./-]+', relative)
            or len(relative.split('/')) > 16
            or any(p in ('', '.', '..') for p in relative.split('/'))
            or not re.search(r'\.(wav|mp3|ogg|flac|gsm|ulaw|alaw|sln|sln16|opus)$', relative, re.I)):
        raise ValueError('Invalid audio path')
    if source == 'files' and not re.fullmatch(
            rf'tenants/(?:{UUID}|[a-fA-F0-9]{{32}})/voip-pabx/'
            r'(?:recordings|media-files)/audio/\d{4}/\d{2}/(?:\d{2}/)?[A-Za-z0-9_-]+\.[A-Za-z0-9]+', relative):
        raise ValueError('Invalid canonical audio path')
    return ROOTS[source] / relative


def open_audio(path):
    """Pin each directory and reject symlinks, devices, FIFOs and hard links."""
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Unsafe audio file')
            if info.st_size > MAX_BYTES:
                raise ValueError('Audio file exceeds transfer budget')
            return os.fdopen(fd, 'rb'), info
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def byte_range(header, size):
    if not header:
        return 0, size, 200
    match = re.fullmatch(r'bytes=(\d*)-(\d*)', header)
    if not match or not any(match.groups()) or size == 0:
        raise ValueError(INVALID_RANGE)
    first, last = match.groups()
    if not first:
        count = int(last)
        if count <= 0:
            raise ValueError(INVALID_RANGE)
        start, end = max(0, size - count), size - 1
    else:
        start, end = int(first), min(int(last), size - 1) if last else size - 1
    if start >= size or end < start:
        raise ValueError(INVALID_RANGE)
    return start, end - start + 1, 206


def inspect_or_delete(request, path, deadline):
    """Only an exact canonical API-media object can be inspected or retired."""
    if request['source'] != 'files':
        raise ValueError('Unsupported file lifecycle source')
    expected = request.get('expectedSha256')
    if not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('An immutable checksum is required')
    try:
        file, before = open_audio(path)
    except FileNotFoundError:
        return {'status': 'complete', 'exists': False}
    with file:
        digest = hashlib.sha256()
        while chunk := file.read(65536):
            if time.time() >= deadline:
                raise TimeoutError('Transfer deadline exceeded')
            digest.update(chunk)
        after = os.fstat(file.fileno())
        if digest.hexdigest() != expected or (before.st_size, before.st_mtime_ns) != (
                after.st_size, after.st_mtime_ns):
            raise ValueError('Audio identity changed')
        if request['action'] == 'delete':
            parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in path.parts[1:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    os.close(parent)
                    parent = child
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_size) != (
                        current.st_dev, current.st_ino, current.st_mtime_ns, current.st_size):
                    raise ValueError('Audio identity changed')
                os.unlink(path.name, dir_fd=parent)
            finally:
                os.close(parent)
        return {'status': 'complete', 'exists': request['action'] != 'delete',
                'sizeBytes': before.st_size, 'sha256': expected}


def validate_request(request):
    api = urlsplit(request['api'])
    if (api.scheme != 'https' or not api.hostname or api.username or api.password
            or api.query or api.fragment or api.path.rstrip('/') not in ('', '/api/v1')):
        raise ValueError('Invalid transfer endpoint')
    for key in ('transferUUID', 'agentUUID', 'leaseUUID'):
        if not re.fullmatch(UUID, request[key]):
            raise ValueError('Invalid transfer identity')
    if request.get('action') not in ('read', 'inspect', 'delete'):
        raise ValueError('Unsupported transfer action')
    deadline = float(request['expiresAt'])
    if not 0 < deadline - time.time() <= 180:
        raise ValueError('Expired transfer')
    token = request['agentToken']
    if not isinstance(token, str) or not token or re.search(r'[\r\n]', token):
        raise ValueError('Invalid transfer authorization')
    return api, deadline


def send_audio(conn, file, length, deadline):
    sent = 0
    while sent < length:
        if time.time() >= deadline:
            raise TimeoutError('Transfer deadline exceeded')
        chunk = file.read(min(65536, length - sent))
        if not chunk:
            raise ValueError('Audio file changed')
        conn.send(chunk)
        sent += len(chunk)
    return sent


def send_headers(conn, request, before, start, length, status):
    # Canonical UUID conversion and a fixed route exclude caller-supplied URL paths.
    transfer_id = str(uuid.UUID(request['transferUUID']))
    conn.putrequest('POST', '/api/v1/filesystem/transfers/' + transfer_id + '/source')
    headers = {
        'Authorization': 'Bearer ' + request['agentToken'],
        'X-MNSCloud-Agent-UUID': request['agentUUID'],
        'X-MNSCloud-Lease-UUID': request['leaseUUID'],
        'Content-Type': 'application/octet-stream',
        'Content-Length': str(length),
        'X-MNSCloud-File-Size': str(before.st_size),
        'X-MNSCloud-Range-Start': str(start),
        'X-MNSCloud-File-Status': str(status),
    }
    for name, value in headers.items():
        conn.putheader(name, value)
    conn.endheaders()


def transfer(request, connection=http.client.HTTPSConnection):
    api, deadline = validate_request(request)
    path = target(request['source'], request['relativePath'])
    if request['action'] != 'read':
        return inspect_or_delete(request, path, deadline)
    file, before = open_audio(path)
    with file:
        start, length, status = byte_range(request.get('range'), before.st_size)
        file.seek(start)
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        conn = connection(api.hostname, api.port or 443,
                          timeout=min(30, deadline - time.time()), context=context)
        try:
            send_headers(conn, request, before, start, length, status)
            sent = send_audio(conn, file, length, deadline)
            after = os.fstat(file.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError('Audio file changed')
            response = conn.getresponse()
            if response.status != 204:
                raise ValueError('Transfer receiver rejected the file')
            return {'status': 'complete', 'bytes': sent}
        finally:
            conn.close()


def alarm_expired(*_):
    raise TimeoutError('Transfer deadline exceeded')


def main():
    signal.signal(signal.SIGALRM, alarm_expired)
    signal.alarm(180)
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise ValueError('Transfer request too large')
        print(json.dumps(transfer(json.loads(raw))))
    except Exception:
        # Never print the exception: network errors may contain authorization or paths.
        print(json.dumps({'status': 'failed'}))
        return 1
    finally:
        signal.alarm(0)
    return 0


if __name__ == '__main__':
    sys.exit(main())
