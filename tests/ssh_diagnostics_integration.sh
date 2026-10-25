#!/usr/bin/env bash
# Requires Docker; all account/sudo mutations happen in a disposable container.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm -i -v "$ROOT_DIR:/agent:ro" \
  debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 bash -s <<'TEST'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 sudo openssh-client procps >/dev/null
# Fresh host: the Agent installer path creates the account with the approved key.
bash /agent/scripts/install-diagnostics.sh | tee /tmp/first
grep -q 'Converged' /tmp/first
grep -qF "$(cut -d' ' -f1-2 /agent/diagnostics/diagnostic-client.pub)" /var/lib/mns-diagnostics/.ssh/authorized_keys
bash /agent/scripts/install-diagnostics.sh | grep -q 'Current; no change'
mkdir -p /var/log/freeradius
printf 'Auth: (0) Login OK: [CANARY.subscriber] (from client X_1 port 0)\n' > /var/log/freeradius/radius.log
mkdir -p /etc/mnscloud
printf 'DB_HOST=127.0.0.1\nDB_PORT=1\nDB_PASS=CANARY_SECRET\nJWT_SECRET=CANARY_JWT\n' > /etc/mnscloud/api.env
chmod 600 /etc/mnscloud/api.env
printf 'step VISIBLE_MARKER apt-get failed\ntoken=CANARY_TOKEN Authorization: Bearer CANARY_BEARER\n' > /var/log/mnscloud-install.log
mkdir -p /var/log/nginx /var/www/mnscloud-app
printf '203.0.113.9 - CANARYUSER [%s] "GET /api/v1/health?token=CANARY HTTP/1.1" 200 1 "-" "CANARY"\n' \
  "$(date '+%d/%b/%Y:%H:%M:%S %z')" > /var/log/nginx/access.log
printf '{"product":"mnscloud-app","version":"0.2.85","gitRef":"v0.2.85","secret":"CANARY"}' > /var/www/mnscloud-app/build.json
for op in config config-check logs logs-text versions connectivity asterisk-odbc artifacts health agent host \
  network timers edge log-usage voip-summary schema-status access-summary; do
  runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND="$op" /usr/local/sbin/mns-diagnostics > "/tmp/$op.json"
  python3 -c 'import json,sys; v=open(sys.argv[1]).read(); json.loads(v); assert "CANARY" not in v' "/tmp/$op.json"
done
grep -q VISIBLE_MARKER /tmp/logs-text.json
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["served"]["mnscloud-app"]["version"] == "0.2.85"' /tmp/artifacts.json
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["total"] == 1 and v["top"][0]["path"] == "/api/v1/health"' /tmp/access-summary.json
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["status"] == "NOT_A_DATABASE_HOST"' /tmp/schema-status.json
runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND='access-summary 60' /usr/local/sbin/mns-diagnostics | grep -q '"sinceMinutes": 60'
runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND='mns-diagnostics versions 2>/dev/null' /usr/local/sbin/mns-diagnostics | grep -q '"diagnostics": "4.3"'
for request in 'access-summary 0' 'access-summary x' 'artifacts /etc/shadow' 'health 8.8.8.8'; do
  if runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND="$request" /usr/local/sbin/mns-diagnostics; then exit 1; fi
done
# Historical filtering reaches older lines through the exact new sudo operation.
mkdir -p /var/log/freeswitch
python3 - <<'FIXTURE'
import base64, json
from pathlib import Path
Path('/var/log/freeswitch/freeswitch.log').write_text('2026-01-02 09:20:00 HISTORICAL token=CANARY_TOKEN\n' + '2026-01-02 11:00:00 recent\n' * 150)
q = {'source':'freeswitch','since':'2026-01-02T09:00:00Z','until':'2026-01-02T10:00:00Z','contains':'HISTORICAL'}
Path('/tmp/query').write_text(base64.urlsafe_b64encode(json.dumps(q).encode()).decode().rstrip('='))
FIXTURE
runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND="log-query $(cat /tmp/query)" /usr/local/sbin/mns-diagnostics > /tmp/historical.json
python3 -c 'import json; s=open("/tmp/historical.json").read(); r=json.loads(s); assert r["complete"] and len(r["lines"]) == 1; assert "CANARY" not in s and "HISTORICAL" in s'
if printf '!!\n' | runuser -u mns-diagnostics -- sudo -n /usr/bin/python3 -I /usr/local/lib/mns-diagnostics/collector.py log-query; then exit 1; fi
if runuser -u mns-diagnostics -- sudo -n /usr/bin/python3 -I /usr/local/lib/mns-diagnostics/collector.py log-query extra; then exit 1; fi
runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND='journal mnscloud-agent 30 err' /usr/local/sbin/mns-diagnostics > /tmp/journal.json
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["unit"] == "mnscloud-agent" and v["sinceMinutes"] == 30' /tmp/journal.json
for request in 'journal sshd' 'journal nginx 9999' 'journal nginx debug' 'journal nginx --grep=x'; do
  if runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND="$request" /usr/local/sbin/mns-diagnostics; then exit 1; fi
done
if printf 'sshd\n' | runuser -u mns-diagnostics -- sudo -n /usr/bin/python3 -I /usr/local/lib/mns-diagnostics/collector.py journal; then exit 1; fi
runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND='container-logs mnscloud-workers 15' /usr/local/sbin/mns-diagnostics > /tmp/container-logs.json
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["container"] == "mnscloud-workers" and v["sinceMinutes"] == 15' /tmp/container-logs.json
for request in 'container-logs' 'container-logs nginx' 'container-logs mnscloud-workers 0' 'container-logs mnscloud-workers --follow'; do
  if runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND="$request" /usr/local/sbin/mns-diagnostics; then exit 1; fi
done
if runuser -u mns-diagnostics -- sudo -n /usr/bin/python3 -I /usr/local/lib/mns-diagnostics/collector.py container-logs mnscloud-workers; then exit 1; fi
if runuser -u mns-diagnostics -- sudo -n /usr/bin/python3 -I /usr/local/lib/mns-diagnostics/collector.py journal nginx; then exit 1; fi
grep -q 'Login OK: \[USER\]' /tmp/logs-text.json
ln -s /etc/shadow /var/log/asterisk-link-test.log
if runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND='logs-text /var/log/asterisk-link-test.log' /usr/local/sbin/mns-diagnostics; then exit 1; fi
if runuser -u mns-diagnostics -- sudo -n /usr/bin/python3 -c 'print("unauthorized")'; then exit 1; fi
if runuser -u mns-diagnostics -- sudo -n /usr/bin/python3 -I /usr/local/lib/mns-diagnostics/collector.py config extra; then exit 1; fi
sha256sum /var/lib/mns-diagnostics/.ssh/authorized_keys > /tmp/key-check
id -u mns-diagnostics > /tmp/uid-check
printf '#!/bin/sh\nprintf "legacy dispatcher\\n"\n' > /usr/local/sbin/mns-diagnostics
rm /usr/local/lib/mns-diagnostics/collector.py /etc/sudoers.d/mns-diagnostics
python3 -I /agent/diagnostics/manage.py --update | tee /tmp/update-result
sha256sum -c /tmp/key-check
test "$(id -u mns-diagnostics)" = "$(cat /tmp/uid-check)"
backup=$(sed -n 's/^Backup directory: //p' /tmp/update-result)
python3 -I /agent/diagnostics/manage.py --rollback "$backup"
test ! -e /etc/sudoers.d/mns-diagnostics
test ! -e /usr/local/lib/mns-diagnostics/collector.py
runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND=help /usr/local/sbin/mns-diagnostics | grep 'legacy dispatcher'
sha256sum -c /tmp/key-check
# Legacy files on an existing account: the Agent path updates in place and keeps the key.
bash /agent/scripts/install-diagnostics.sh | grep -q 'Converged'
runuser -u mns-diagnostics -- env SSH_ORIGINAL_COMMAND=help /usr/local/sbin/mns-diagnostics | grep -q 'journal UNIT'
sha256sum -c /tmp/key-check
printf 'PASS: Agent-managed install/idempotence/update, collectors (diagnostics 4.3), masked usernames, denied sudo, key/UID preservation and rollback.\n'
TEST
