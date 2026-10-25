"""Security regression checks; no account installation or remote connections."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'diagnostics'
spec = importlib.util.spec_from_file_location('collector', SOURCE / 'collector.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

class DiagnosticsContract(unittest.TestCase):
    def test_syntax(self):
        subprocess.run(['sh', '-n', str(SOURCE / 'dispatcher.sh')], check=True)
        for path in SOURCE.glob('*.py'):
            compile(path.read_text(), str(path), 'exec')
        doc = (ROOT / 'docs/ssh-diagnostics.md').read_text()
        block = doc.split('```bash\n', 1)[1].split('\n```', 1)[0]
        subprocess.run(['bash', '-n'], input=block, text=True, check=True)

    def test_dispatcher_allowed_and_denied(self):
        for command in ('help', 'identity', 'memory', 'uptime'):
            result = subprocess.run(['/bin/sh', str(SOURCE / 'dispatcher.sh')], env={'SSH_ORIGINAL_COMMAND': command}, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.stdout.strip())
        for command in ('sh -c id', 'id', 'config extra', 'logs-text extra', 'logs-text /etc/shadow', 'config; id', 'logs\nid', '$(id)', '`id`', 'services --all', 'cat /etc/passwd', 'internal-sftp', ' config', 'config ', 'journal', 'journalctl -u nginx'):
            result = subprocess.run(['/bin/sh', str(SOURCE / 'dispatcher.sh')], env={'SSH_ORIGINAL_COMMAND': command}, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 126, command)
            self.assertEqual(result.stdout, '')
            self.assertIn('DENIED', result.stderr)

    def test_collector_rejects_arguments_before_privilege(self):
        for args in ([], ['config', '/etc/shadow'], ['shell'], ['logs;id'], ['logs-text', '/etc/shadow']):
            result = subprocess.run(['python3', '-I', str(SOURCE / 'collector.py'), *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 126)
            self.assertNotIn('Traceback', result.stderr)

    def test_journal_parameters_are_validated_before_privilege(self):
        for request in ('', 'sshd', 'nginx 0', 'nginx 1441', 'nginx debug', 'nginx 10 err x', 'nginx err 10',
                        'nginx\nid', 'nginx;id', '../nginx', 'nginx  10', '--unit=sshd', 'nginx --grep=x',
                        'nginx ' + '1' * 300, 'nginx \xe9'):
            result = subprocess.run(['python3', '-I', str(SOURCE / 'collector.py'), 'journal'],
                                    input=request.encode('latin-1') + b'\n', capture_output=True)
            self.assertEqual(result.returncode, 126, repr(request))
            self.assertEqual(result.stdout, b'')
            self.assertIn(b'DENIED', result.stderr)
        self.assertEqual(collector.parse_journal_request('mnscloud-api\n'), ('mnscloud-api', 60, 'info'))
        self.assertEqual(collector.parse_journal_request('mnscloud-api 1440 err'), ('mnscloud-api', 1440, 'err'))
        self.assertEqual(collector.parse_journal_request('mnscloud-api warning'), ('mnscloud-api', 60, 'warning'))

    def test_journal_is_bounded_and_masked(self):
        raw = json.dumps({'__REALTIME_TIMESTAMP': '1760500000000000', 'PRIORITY': '3',
                          'MESSAGE': 'login failed token=abc Authorization: Bearer xyz'})
        self.assertEqual(collector.journal_lines(raw),
                         ['2025-10-15T03:46:40.000000Z 3 login failed token=[REDACTED] Authorization: [REDACTED] [REDACTED]'])
        with patch.object(collector, 'run', return_value='') as run:
            result = collector.journal('mnscloud-api 30 warning')
        args = run.call_args.args[0]
        self.assertIn('--unit=mnscloud-api.service', args)
        self.assertIn('--since=-30min', args)
        self.assertIn('--priority=warning', args)
        self.assertIn('--lines=2000', args)
        self.assertEqual(result['lines'], [])
        dispatcher = (SOURCE / 'dispatcher.sh').read_text()
        self.assertIn('journal\\ *|container-logs\\ *|access-summary\\ *)', dispatcher)
        manage = (SOURCE / 'manage.py').read_text()
        self.assertIn("'journal'", manage)

    def test_container_logs_parameters_are_validated_before_privilege(self):
        for request in ('', 'nginx', 'docker', 'mnscloud-workers 0', 'mnscloud-workers 1441', 'mnscloud-workers err',
                        'mnscloud-workers 10 x', 'mnscloud-workers\nid', 'mnscloud-workers;id', '../mnscloud-workers',
                        'mnscloud-workers  10', '--since=1h', 'mnscloud-workers --follow', 'MNSCLOUD-WORKERS'):
            result = subprocess.run(['python3', '-I', str(SOURCE / 'collector.py'), 'container-logs'],
                                    input=request.encode('latin-1') + b'\n', capture_output=True)
            self.assertEqual(result.returncode, 126, repr(request))
            self.assertEqual(result.stdout, b'')
            self.assertIn(b'container-logs CONTAINER [MINUTES]', result.stderr)
        self.assertEqual(collector.parse_container_request('mnscloud-workers\n'), ('mnscloud-workers', 60))
        self.assertEqual(collector.parse_container_request('mnscloud-workers 1440'), ('mnscloud-workers', 1440))

    def test_container_logs_are_bounded_ordered_and_masked(self):
        raw = ('2026-10-25T01:00:02.000000000Z [worker] handler=hr-timesheet claimed=2\n'
               '2026-10-25T01:00:01.000000000Z [worker] error token=abc Authorization: Bearer xyz\n')
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return raw

        result = collector.container_logs('mnscloud-workers 30', runner=runner)
        args, kwargs = calls[0]
        self.assertEqual(args, ['/usr/bin/docker', 'logs', '--timestamps', '--since', '30m', '--tail', '2000',
                                'mnscloud-workers'])
        self.assertTrue(kwargs['stderr'])
        self.assertEqual(result['lines'], [
            '2026-10-25T01:00:01.000000000Z [worker] error token=[REDACTED] Authorization: [REDACTED] [REDACTED]',
            '2026-10-25T01:00:02.000000000Z [worker] handler=hr-timesheet claimed=2'])
        self.assertEqual(result['container'], 'mnscloud-workers')

        def missing(args, **kwargs):
            raise subprocess.CalledProcessError(1, args)

        self.assertEqual(collector.container_logs('mnscloud-api', runner=missing)['lines'], 'UNAVAILABLE')
        dispatcher = (SOURCE / 'dispatcher.sh').read_text()
        self.assertIn('journal\\ *|container-logs\\ *|access-summary\\ *)', dispatcher)
        self.assertIn("'container-logs'", (SOURCE / 'manage.py').read_text())

    def test_env_is_literal(self):
        value = collector.parse_env("DB_PASS='$(id); `id`'\nUNKNOWN=secret\n")
        self.assertEqual(value['DB_PASS'], '$(id); `id`')
        self.assertEqual(collector.public_value('DB_PASS', value['DB_PASS']), 'SET')
        for text in ('DB_PASS=a\nDB_PASS=b', "DB_PASS='multiline\nsecret'", 'source /etc/profile'):
            with self.assertRaises(ValueError):
                collector.parse_env(text)

    def test_redaction(self):
        values = {'DB_PASS': 'CANARY_PASSWORD', 'JWT_SECRET': 'CANARY_JWT', 'UNKNOWN': 'CANARY_UNKNOWN', 'RABBITMQ_URL': 'amqp://user:CANARY_URL@broker.example:5672/CANARY_PATH?key=CANARY_QUERY#CANARY_FRAGMENT', 'DB_HOST': 'db.example', 'DB_PORT': '3306'}
        result = json.dumps(collector.config_report({'api': values}))
        self.assertNotIn('CANARY', result)
        self.assertIn('broker.example', result)
        self.assertEqual(collector.public_value('DB_PASS', ''), 'EMPTY')
        self.assertEqual(collector.public_value('RABBITMQ_URL', 'file:///etc/shadow'), 'INVALID_ENDPOINT')

    def test_config_checks(self):
        result = collector.config_report({'workers': {'WORKER_HANDLERS': 'agent-health'}, 'api': {'DENO_ENV': 'production', 'APP_DEBUG': 'true', 'DB_PORT': '0'}}, True)
        self.assertIn({'key': 'DB_PASS', 'status': 'MISSING'}, result['workers']['issues'])
        self.assertIn({'key': 'APP_DEBUG', 'status': 'DISABLE_IN_PRODUCTION'}, result['api']['issues'])
        self.assertIn({'key': 'DB_PORT', 'status': 'INVALID_PORT'}, result['api']['issues'])

    def test_logs_never_return_raw_fields(self):
        raw = json.dumps({'MESSAGE': 'Error password=CANARY Bearer secret email@example.com', '__REALTIME_TIMESTAMP': '123', 'PRIORITY': '3', '_HOSTNAME': 'CANARY'})
        self.assertEqual(collector.summarize_logs(raw), [{'timestamp_us': '123', 'priority': '3', 'category': 'ERROR'}])
        malicious = json.dumps({'MESSAGE': 'CANARY', '__REALTIME_TIMESTAMP': 'CANARY', 'PRIORITY': 'CANARY'})
        self.assertNotIn('CANARY', json.dumps(collector.summarize_logs(malicious)))

    def test_log_text_masks_secrets(self):
        lines = [
            'curl -H "Authorization: Bearer CANARY_BEARER" https://api.example',
            'token=CANARY_TOKEN password: CANARY_PASSWORD DB_PASS="CANARY_DB"',
            'jwt eyJhbGciOiJIUzI1NiJ9.eyJDQU5BUlkiOjF9.CANARYsignature',
            'amqp://user:CANARY_URL@broker.example:5672/',
            '--api-token CANARY_FLAG --password=CANARY_FLAG2',
            'staged 1C3A57D9B85511F1935FBC2411F7DD2DCANARY',
            '"secret": "CANARY_JSON", "api_key":"CANARY_KEY"',
            '-----BEGIN OPENSSH PRIVATE KEY----- CANARY_PEM',
        ]
        for line in lines:
            self.assertNotIn('CANARY', collector.mask_line(line), line)
        visible = collector.mask_line('\x1b[31mE: Unable to locate package unixodbc-dev\x1b[0m\x07')
        self.assertEqual(visible, 'E: Unable to locate package unixodbc-dev')
        self.assertTrue(collector.mask_line('x' * 1000).endswith('[TRUNCATED]'))

    def test_log_text_reader_rejects_links_and_bounds_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'install.log'
            path.write_text(''.join(f'line {i} token=CANARY{i}\n' for i in range(500)))
            result = collector.tail_log(path)
            lines = result['tail']
            self.assertEqual(len(lines), collector.LOG_TEXT_LINES)
            self.assertEqual(lines[-1], 'line 499 token=[REDACTED]')
            self.assertNotIn('CANARY', json.dumps(result))
            link = Path(folder) / 'link.log'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                collector.tail_log(link)
            hard = Path(folder) / 'hard.log'
            hard.hardlink_to(path)
            with self.assertRaises(ValueError):
                collector.tail_log(hard)

    def test_highlights_survive_long_post_failure_output(self):
        lines = ['step 1 ok', 'apt-get install x', 'E: Unable to locate package CANARY password=CANARY',
                 'Last failed command: apt-get install x'] + [f'#define SUMMARY_{i} 1' for i in range(300)]
        found = collector.highlights(lines)
        self.assertIn('4: Last failed command: apt-get install x', found)
        self.assertTrue(any(line.startswith('3: E: Unable to locate package') for line in found))
        self.assertIn('1: step 1 ok', found)  # context before the failure
        self.assertNotIn('password=CANARY', json.dumps(found))
        self.assertLessEqual(len(collector.highlights(['error'] * 500)), collector.LOG_HIGHLIGHT_LINES)

    def test_journal_text_is_masked(self):
        raw = json.dumps({'MESSAGE': 'failed password=CANARY', '__REALTIME_TIMESTAMP': '123'})
        self.assertEqual(collector.journal_text(raw), ['123 failed password=[REDACTED]'])

    def test_voip_engines_are_covered(self):
        dispatcher = (SOURCE / 'dispatcher.sh').read_text()
        for unit in ('asterisk', 'freeswitch', 'kamailio', 'opensips'):
            self.assertIn(unit, collector.UNITS)
            self.assertIn(unit + '.service', dispatcher)
        self.assertEqual(collector.LOG_FILES['kamailio-err'], Path('/var/log/mnscloud/kamailio/kamailio.err.log'))
        self.assertEqual(collector.LOG_FILES['kamailio-out'], Path('/var/log/mnscloud/kamailio/kamailio.out.log'))
        for checkout in ('asterisk', 'freeswitch', 'kamailio-softswitch', 'opensips-sbc'):
            self.assertIn(checkout, collector.CHECKOUTS)

    def test_realtime_edges_are_covered(self):
        dispatcher = (SOURCE / 'dispatcher.sh').read_text()
        for unit in ('rtpengine-daemon', 'mnscloud-media-heartbeat', 'coturn', 'mnscloud-turn-sync',
                     'mnscloud-webrtc-sync', 'kamailio', 'nginx'):
            self.assertIn(unit, collector.UNITS)
            self.assertIn(unit + '.service', dispatcher)
        self.assertEqual(collector.LOG_FILES['turn'], Path('/var/log/mnscloud/turn/turnserver.log'))
        for checkout in ('media', 'turn', 'kamailio-webrtc'):
            self.assertIn(checkout, collector.CHECKOUTS)
        with patch.object(collector, 'run', side_effect=OSError), \
                patch.object(collector, 'trusted_read', side_effect=OSError):
            result = collector.versions()
        self.assertEqual(result['diagnostics'], '4.2')
        for key in ('rtpengine-daemon', 'coturn', 'clickhouse-server', 'vector', 'pdns-server', 'pdns-recursor',
                    'dnsdist', 'dns_checkout_version', 'media_checkout_version',
                    'turn_checkout_version', 'logs_checkout_version',
                    'kamailio-webrtc_checkout_version'):
            self.assertEqual(result[key], 'UNAVAILABLE')

    def test_db_reports_newest_prepared_release_not_base_checkout(self):
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root) / 'mnscloud-db-releases'
            parent.mkdir()
            for name in ('v0.1.9-' + 'a' * 64, 'v0.1.10-' + 'b' * 64, 'v0.1.2-' + 'c' * 64, 'notes'):
                (parent / name).mkdir()
            with patch.object(Path, 'lstat', return_value=os.stat_result((0o40755, 0, 0, 0, 0, 0, 0, 0, 0, 0))):
                self.assertEqual(collector.db_release_version(parent), '0.1.10')
            self.assertEqual(collector.db_release_version(Path(root) / 'missing'), 'UNAVAILABLE')
        with patch.object(collector, 'run', side_effect=OSError), \
                patch.object(collector, 'trusted_read', side_effect=OSError):
            result = collector.versions()
        self.assertNotIn('db_checkout_version', result)
        self.assertIn('db_release_version', result)

    def test_asterisk_odbc_reports_pool_state_without_dsn(self):
        sample = ('ODBC DSN Settings\n-----------------\n\n  Name:   mnscloud\n  DSN:    CANARY_DSN\n'
                  '    Number of active connections: 1 (out of 1)\n    Logging: Disabled\n')
        with patch.object(collector, 'run', return_value=sample):
            result = collector.asterisk_odbc()
        self.assertEqual(result['status'], 'OK')
        self.assertEqual(result['pools'], [{'name': 'mnscloud', 'active': 1, 'max': 1, 'status': 'CONNECTED'}])
        self.assertNotIn('CANARY', json.dumps(result))
        with patch.object(collector, 'run', side_effect=OSError):
            self.assertEqual(collector.asterisk_odbc()['status'], 'ASTERISK_UNAVAILABLE')

    def test_connectivity_has_no_credentials(self):
        with patch.object(collector.socket, 'create_connection', side_effect=OSError) as connect:
            result = collector.connectivity({'api': {'RABBITMQ_URL': 'amqp://user:secret@broker.example:5672/'}})
            connect.assert_called_once_with(('broker.example', 5672), timeout=2)
            self.assertNotIn('secret', json.dumps(result))

    def test_reader_rejects_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'env'
            path.write_text('DB_PASS=CANARY')
            with self.assertRaises(ValueError):
                collector.trusted_read(path)
            link = Path(folder) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                collector.trusted_read(link)

    def test_platform_modules_are_covered(self):
        dispatcher = (SOURCE / 'dispatcher.sh').read_text()
        for unit in ('mnscloud-authentication', 'mnscloud-authentication-config', 'mnscloud-openvault',
                     'mnscloud-openvault-tls-renew', 'mnscloud-webapps', 'mnscloud-webapps-sync', 'incus',
                     'mnscloud-grow-rootfs', 'mnscloud-agent', 'mnscloud-logs-storage', 'mnscloud-logs-ingest',
                     'mnscloud-logs-config', 'pdns', 'pdns-recursor', 'dnsdist'):
            self.assertIn(unit, collector.UNITS)
            self.assertIn(unit + '.service', dispatcher)
        for name in ('authentication', 'openvault', 'logs', 'dns'):
            self.assertIn(name, collector.FILES)
        for checkout in ('webapps', 'agent'):
            self.assertIn(checkout, collector.CHECKOUTS)
        self.assertEqual(collector.LOG_FILES['agent-install'], Path('/var/log/mnscloud-agent-install.log'))
        self.assertEqual(collector.LOG_FILES['freeradius'], Path('/var/log/freeradius/radius.log'))

    def test_module_env_values_fail_closed(self):
        values = {'DB_PASS': 'CANARY_DB', 'DB_HOST': '10.0.0.5', 'AUTHENTICATION_LISTEN_ADDRESS': '10.0.0.9',
                  'AUTHENTICATION_SERVER_UUID': '83F11847C7E511F19300BC2411F7DD2D',
                  'MNSCLOUD_API_BASE_URL': 'https://api.example/api/v1?token=CANARY_Q'}
        result = json.dumps(collector.config_report({'authentication': values}))
        self.assertNotIn('CANARY', result)
        self.assertIn('10.0.0.9', result)
        vault = {'OPENVAULT_AWSKMS_KEY_ID': 'arn:aws:kms:CANARY', 'OPENVAULT_NODE_ID': 'openvault-prod1'}
        self.assertNotIn('CANARY', json.dumps(collector.config_report({'openvault': vault})))
        checks = collector.config_report({'authentication': {'DB_HOST': 'x'}}, True)
        self.assertIn({'key': 'DB_PASS', 'status': 'MISSING'}, checks['authentication']['issues'])

    def test_radius_log_masks_usernames(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'radius.log'
            path.write_text('Wed Oct 14 08:13:22 2026 : Auth: (0) Login OK: [CANARY.user] (from client X_1 port 0)\n'
                            'Wed Oct 14 08:13:23 2026 : Auth: (2) Login incorrect: [CANARY2] (from client X_1 port 0)\n'
                            'Wed Oct 14 08:13:24 2026 : Error: rlm_sql failed\n')
            result = collector.tail_log(path, mask_users=True)
            self.assertNotIn('CANARY', json.dumps(result))
            self.assertIn('Login OK: [USER] (from client X_1 port 0)', result['tail'][0])
            self.assertTrue(any('rlm_sql failed' in line for line in result['highlights']))
            self.assertIn('CANARY', json.dumps(collector.tail_log(path)))  # only the engine log is user-masked


def dispatch(command):
    return subprocess.run(['/bin/sh', str(SOURCE / 'dispatcher.sh')], env={'SSH_ORIGINAL_COMMAND': command},
                          capture_output=True, text=True, timeout=20)


class DiagnosticsV4Contract(unittest.TestCase):
    def test_operation_lists_agree(self):
        spec_manage = importlib.util.spec_from_file_location('manage', SOURCE / 'manage.py')
        manage = importlib.util.module_from_spec(spec_manage)
        spec_manage.loader.exec_module(manage)
        self.assertEqual(set(manage.OPERATIONS), set(collector.OPERATIONS))
        help_text = dispatch('help').stdout
        for operation in collector.OPERATIONS:
            self.assertIn('  ' + operation, help_text)
        self.assertIn('diagnostics ' + collector.DIAGNOSTICS_VERSION, help_text)

    def test_runtime_products_are_covered(self):
        # Every runtime product the Agent reports must be readable by artifacts and versions.
        main = (ROOT / 'main.ts').read_text()
        block = main.split('async function collectRuntimeVersions', 1)[1].split('runtimeVersionCache = {', 1)[0]
        products = set(__import__('re').findall(r'"/opt/mnscloud/mnscloud-([a-z0-9-]+)"', block))
        # Conventional module runtimes are reported from one list (main.ts CONVENTIONAL_MODULE_RUNTIMES).
        conventional = main.split('const CONVENTIONAL_MODULE_RUNTIMES = [', 1)[1].split(']', 1)[0]
        products |= set(__import__('re').findall(r'"([a-z0-9-]+)"', conventional))
        self.assertTrue(products)
        self.assertEqual(products, set(collector.RUNTIME_CHECKOUTS))
        for product in products:
            self.assertTrue(product in collector.FILES or product in collector.CHECKOUTS
                            or product in ('kamailio-webrtc',), product)

    def test_dispatcher_normalizes_habits_but_still_denies(self):
        for command in ('mns-diagnostics help', 'help 2>/dev/null', 'help 2>&1', 'mns-diagnostics uptime 2>/dev/null'):
            result = dispatch(command)
            self.assertEqual(result.returncode, 0, command)
            self.assertTrue(result.stdout.strip())
        for command in ('help; id', 'help 2>/tmp/x', 'help 2>/dev/null; id', 'mns-diagnostics sh -c id',
                        'help 2>&1 2>&1', 'artifacts x', 'health 8.8.8.8', 'access-summary', 'access-summaryx',
                        'schema-status SELECT'):
            if command == 'access-summary':
                continue  # valid; needs the sudo collector
            result = dispatch(command)
            self.assertEqual(result.returncode, 126, command)
            self.assertEqual(result.stdout, '')
            self.assertIn("Run 'help'", result.stderr)
        identity = dispatch('identity')
        self.assertEqual(identity.returncode, 0)
        self.assertEqual(len(identity.stdout.strip().splitlines()), 2)

    def test_parameters_are_validated_before_privilege(self):
        for request in ('abc', '0', '1441', '10 10', '-5', '10;id', '9' * 10):
            result = subprocess.run(['python3', '-I', str(SOURCE / 'collector.py'), 'access-summary'],
                                    input=request.encode() + b'\n', capture_output=True)
            self.assertEqual(result.returncode, 126, request)
            self.assertIn(b'DENIED', result.stderr)
        self.assertEqual(collector.parse_access_request('\n'), 15)
        self.assertEqual(collector.parse_access_request('120\n'), 120)
        self.assertEqual(collector.parse_journal_request('mnscloud-asterisk-logs 30'), ('mnscloud-asterisk-logs', 30, 'info'))
        for request in ('mnscloud-', 'mnscloud--x', 'mnscloudx', 'sshd-mnscloud-x'):
            with self.assertRaises(PermissionError):
                collector.parse_journal_request(request)
        for args in (['artifacts', 'x'], ['health', '/etc/shadow'], ['schema-status', 'SELECT 1']):
            result = subprocess.run(['python3', '-I', str(SOURCE / 'collector.py'), *args], capture_output=True)
            self.assertEqual(result.returncode, 126)

    def test_access_summary_aggregates_without_clients_queries_or_agents(self):
        now = collector.datetime(2026, 10, 19, 16, 0, tzinfo=collector.timezone.utc)
        rows = [
            '203.0.113.9 - CANARYUSER [19/Oct/2026:12:58:00 -0300] "POST /api/v1/system/ai/providers/'
            '9F1C2E3D4B5A69788796A5B4C3D2E1F0?token=CANARY HTTP/2.0" 200 155 "-" "CANARY-agent"',
            '2804:8094::1 - - [19/Oct/2026:12:59:00 -0300] "GET /api/v1/tenants/12345/domains/CANARY.example.com '
            'HTTP/2.0" 404 70 "https://CANARY.example/" "Deno/2.8.1"',
            '198.51.100.7 - - [19/Oct/2026:11:00:00 -0300] "GET /old HTTP/1.1" 200 1 "-" "-"',
            'garbage CANARY line',
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_text('\n'.join(rows) + '\n')
            result = collector.access_summary(15, path, now)
        text = json.dumps(result)
        self.assertNotIn('CANARY', text)
        self.assertNotIn('203.0.113.9', text)
        self.assertEqual(result['total'], 2)
        self.assertTrue(result['windowComplete'])
        self.assertIn({'method': 'POST', 'path': '/api/v1/system/ai/providers/:id', 'status': 200, 'count': 1},
                      result['top'])
        self.assertIn({'method': 'GET', 'path': '/api/v1/tenants/:id/domains/:value', 'status': 404, 'count': 1},
                      result['top'])
        self.assertEqual(collector.normalize_path('/a/b/c/d/e/f/g/h/i/j'), '/a/b/c/d/e/f/g/h/...')

    def test_agent_events_keep_listed_fields_only(self):
        lines = [
            {'PRIORITY': '6', 'MESSAGE': '[mnscloud-agent] 2026-10-19T16:35:33.418Z Runtime update completed. '
                                         '{"jobUUID":"65372109189346B2A10139BF13688E02","product":"mnscloud-app",'
                                         '"targetRef":"v0.2.86","scheduled":false,"password":"CANARY","nested":{"x":1}}'},
            {'PRIORITY': '4', 'MESSAGE': '[mnscloud-agent] 2026-10-19T16:36:00.000Z Failed to report job failure. '
                                         '{"error":"POST failed Authorization: Bearer CANARY_TOKEN"}'},
            {'PRIORITY': '6', 'MESSAGE': '[mnscloud-agent] 2026-10-19T16:38:54.096Z Agent resource usage. '
                                         '{"rssBytes":97243136,"uptimeSeconds":38529,"jobPolling":false}'},
            {'PRIORITY': '6', 'MESSAGE': 'unrelated CANARY output'},
        ]
        result = collector.agent_events('\n'.join(json.dumps(line) for line in lines))
        text = json.dumps(result)
        self.assertNotIn('CANARY', text)
        self.assertEqual(result['events'][0]['targetRef'], 'v0.2.86')
        self.assertNotIn('password', result['events'][0])
        self.assertEqual(result['events'][1]['level'], 'warn')
        self.assertEqual(result['resource']['rssBytes'], 97243136)
        self.assertEqual(result['levels24h'], {'info': 2, 'warn': 1})

    def test_health_targets_are_local_and_fields_are_listed(self):
        self.assertEqual(collector.local_address('0.0.0.0'), '127.0.0.1')
        self.assertEqual(collector.local_address('127.0.0.1'), '127.0.0.1')
        self.assertIsNone(collector.local_address('8.8.8.8'))
        self.assertIsNone(collector.local_address('api.example.com'))
        targets = collector.health_targets({'api': {'APP_HOST': '8.8.8.8', 'APP_PORT': '8000'},
                                            'openvault': {'OPENVAULT_MODE': 'x'}}, {'WEBAPPS_LISTEN_PORT': '99999'},
                                           True)
        by_name = {target['name']: target for target in targets}
        self.assertEqual(by_name['api']['configError'], 'NOT_A_LOCAL_ADDRESS_OR_PORT')
        self.assertEqual(by_name['webapps']['configError'], 'NOT_A_LOCAL_ADDRESS_OR_PORT')
        self.assertEqual((by_name['app']['host'], by_name['app']['port'], by_name['app']['path']),
                         ('127.0.0.1', 8080, '/build.json'))
        self.assertTrue(by_name['openvault']['path'].startswith('/v1/sys/health?'))
        self.assertNotIn('logs-clickhouse', by_name)

        class Response:
            status = 200

            def read(self, size):
                return json.dumps({'status': 'ok', 'version': '1.3.661', 'database': 'connected',
                                   'secret': 'CANARY', 'environment': {'nested': 'CANARY'}}).encode()

            def getheader(self, name):
                return None

        class Connection:
            def request(self, method, path, headers):
                assert method == 'GET' and 'Authorization' not in headers

            def getresponse(self):
                return Response()

            def close(self):
                pass

        api = {'name': 'api', 'scheme': 'http', 'host': '127.0.0.1', 'port': 8000, 'path': '/health',
               'configError': None}
        result = collector.probe(api, lambda target: Connection())
        self.assertEqual(result['status'], 'OK')
        self.assertEqual(result['fields'], {'status': 'ok', 'version': '1.3.661', 'database': 'connected'})
        self.assertNotIn('CANARY', json.dumps(result))
        dropped = []
        with patch.object(collector, 'load_configs', return_value={}), \
                patch.object(collector, 'trusted_read', side_effect=FileNotFoundError), \
                patch.object(collector, 'probe', side_effect=lambda target: {'name': target['name']}):
            collector.health(drop=lambda: dropped.append(True))
        self.assertEqual(dropped, [True])

    def test_artifacts_read_listed_build_fields_inside_release_tree(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            release = root / 'releases' / 'pos' / 'v1.0.11-abc'
            release.mkdir(parents=True)
            (release / 'build.json').write_text(json.dumps({'product': 'mnscloud-pos', 'version': '1.0.11',
                                                            'ref': 'v1.0.11', 'token': 'CANARY',
                                                            'buildRef': 'x; rm -rf /'}))
            (release / 'index.html').write_text('<html>')
            (root / 'current').mkdir()
            (root / 'current' / 'pos').symlink_to(release)
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'build.json').write_text('{"version": "CANARY"}')
            (root / 'current' / 'evil').symlink_to(outside)
            result = collector.webapps_artifacts(root)
        self.assertEqual(result['evil'], 'UNEXPECTED_RELEASE_TARGET')
        self.assertEqual(result['pos']['version'], '1.0.11')
        self.assertEqual(result['pos']['release'], 'v1.0.11-abc')
        self.assertEqual(result['pos']['buildRef'], 'REDACTED')
        self.assertEqual(len(result['pos']['indexSha256']), 64)
        self.assertNotIn('CANARY', json.dumps(result))
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'VERSION').write_text('v1.3.661\n')
            self.assertEqual(collector.build_metadata(Path(folder)), {'version': 'v1.3.661'})
            link = Path(folder) / 'linked'
            link.mkdir()
            (link / 'build.json').symlink_to('/etc/hostname')
            self.assertEqual(collector.build_metadata(link)['build'], 'UNREADABLE_OR_UNSAFE')

    def test_network_listeners_have_no_processes(self):
        sample = ('tcp   LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1,fd=6))\n'
                  'tcp   LISTEN 0 4096 [::]:22 [::]:*\nudp   UNCONN 0 0 172.17.0.100:5060 0.0.0.0:*\n')
        self.assertEqual(collector.parse_listeners(sample), [
            {'proto': 'tcp', 'address': '[::]', 'port': 22}, {'proto': 'tcp', 'address': '0.0.0.0', 'port': 443},
            {'proto': 'udp', 'address': '172.17.0.100', 'port': 5060}])

    def test_voip_summary_returns_counters_only(self):
        outputs = {
            'stats.get_statistics': 'usrloc:registered_users = 3\nusrloc:location_contacts = 4\nCANARY = x\n',
            'core show channels count': '2 active channels\n1 active call\n9 calls processed\n',
            'pjsip show contacts': 'Contact: CANARY/sip:1001@10.0.0.1\n\nObjects found: 5\n',
            'pjsip show endpoints': 'Objects found: 7\n',
            'pjsip show registrations': 'No objects found.\n',
        }

        def runner(args):
            for key, value in outputs.items():
                if key in args:
                    return value
            raise OSError

        tools = {name: '/bin/sh' if name in ('kamailio', 'asterisk') else '/nonexistent' for name in collector.VOIP_TOOLS}
        with patch.dict(collector.VOIP_TOOLS, tools):
            result = collector.voip_summary(runner)
        self.assertEqual(result['kamailio'], {'usrloc:registered_users': 3, 'usrloc:location_contacts': 4})
        self.assertEqual(result['asterisk'], {'activeChannels': 2, 'activeCalls': 1, 'callsProcessed': 9,
                                              'pjsipContacts': 5, 'pjsipEndpoints': 7, 'pjsipRegistrations': 0})
        self.assertNotIn('freeswitch', result)
        self.assertNotIn('CANARY', json.dumps(result))

    def test_schema_status_uses_fixed_queries_after_dropping_privileges(self):
        calls, dropped = [], []

        def runner(sql):
            calls.append(sql)
            if 'SchemaAppliedRevision' in sql:
                return 'primary\tv0.1.495\t2026-10-19 16:00:00.000000\n'
            return 'verify\tv0.1.495\tsuccess\t2026-10-19 16:00:00\tNULL\tNULL\t2026-10-19 15:59:00\n'

        with patch.object(collector, 'trusted_read', return_value='DB_NAME=clouddb\nDB_ROOT_PASSWORD=CANARY\n'):
            result = collector.schema_status(drop=lambda: dropped.append(True), runner=runner)
        self.assertEqual(dropped, [True])
        self.assertEqual(calls, [collector.SCHEMA_REVISION_SQL, collector.SCHEMA_JOBS_SQL])
        self.assertEqual(result['appliedRevisions'][0]['releaseTag'], 'v0.1.495')
        self.assertIsNone(result['reconcileJobs'][0]['finishedAt'])
        self.assertNotIn('CANARY', json.dumps(result))
        with patch.object(collector, 'trusted_read', side_effect=FileNotFoundError):
            self.assertEqual(collector.schema_status(drop=lambda: None)['status'], 'NOT_A_DATABASE_HOST')
        for sql in (collector.SCHEMA_REVISION_SQL, collector.SCHEMA_JOBS_SQL):
            self.assertTrue(sql.startswith('SELECT '))
            self.assertNotIn('Message', sql)
            self.assertNotIn('Json', sql)

    def test_db_account_grants_are_column_scoped(self):
        spec_db = importlib.util.spec_from_file_location('db_account', SOURCE / 'db_account.py')
        db_account = importlib.util.module_from_spec(spec_db)
        spec_db.loader.exec_module(db_account)
        tables = {'SchemaAppliedRevision', 'SchemaReconcileJob'}
        allowed = [
            'GRANT USAGE ON *.* TO `mns-diagnostics`@`localhost` IDENTIFIED VIA unix_socket',
            'GRANT SELECT (`SarStatus`, `SarClusterKey`) ON `clouddb`.`SchemaAppliedRevision` TO `mns-diagnostics`@`localhost`',
        ]
        self.assertEqual(db_account.unexpected_grants(allowed, 'clouddb', tables), [])
        for line in ('GRANT SELECT ON `clouddb`.`Secret` TO `mns-diagnostics`@`localhost`',
                     'GRANT SELECT (`SrjLastErrorMessage`) ON `clouddb`.`SchemaReconcileJob` TO `mns-diagnostics`@`localhost`',
                     'GRANT SELECT (`SarStatus`) ON `otherdb`.`SchemaAppliedRevision` TO `mns-diagnostics`@`localhost`',
                     'GRANT ALL PRIVILEGES ON *.* TO `mns-diagnostics`@`localhost`'):
            self.assertEqual(db_account.unexpected_grants(allowed + [line], 'clouddb', tables), [line])
        statements = []

        def run(statement, database, password):
            statements.append(statement)
            if statement.startswith('SELECT TABLE_NAME'):
                return 'SchemaAppliedRevision\nSchemaReconcileJob\n'
            if statement.startswith('SHOW GRANTS'):
                return '\n'.join(allowed) + '\n'
            return ''

        with patch.object(db_account, 'DB_ENV', Path('/etc/hostname')), \
                patch.object(db_account, 'MARIADB', Path('/bin/sh')), \
                patch.object(db_account.pwd, 'getpwnam'), \
                patch.object(db_account, 'private_env', return_value={'DB_NAME': 'clouddb'}):
            self.assertEqual(db_account.converge(run)['status'], 'CONVERGED')
        self.assertIn("CREATE USER IF NOT EXISTS 'mns-diagnostics'@'localhost' IDENTIFIED VIA unix_socket;", statements)
        self.assertFalse(any('IDENTIFIED BY' in statement or 'PASSWORD' in statement for statement in statements))
        self.assertFalse(any(statement.startswith('REVOKE') for statement in statements))


if __name__ == '__main__':
    unittest.main()
