"""Security regression checks; no account installation or remote connections."""
import importlib.util
import json
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
        self.assertIn('collector.py journal\n', dispatcher)
        manage = (SOURCE / 'manage.py').read_text()
        self.assertIn("'journal'", manage)

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
        self.assertEqual(result['diagnostics'], '3.7')
        for key in ('rtpengine-daemon', 'coturn', 'media_checkout_version', 'turn_checkout_version',
                    'kamailio-webrtc_checkout_version'):
            self.assertEqual(result[key], 'UNAVAILABLE')

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
                     'mnscloud-grow-rootfs', 'mnscloud-agent'):
            self.assertIn(unit, collector.UNITS)
            self.assertIn(unit + '.service', dispatcher)
        for name in ('authentication', 'openvault'):
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

if __name__ == '__main__':
    unittest.main()
