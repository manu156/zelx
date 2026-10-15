#!/usr/bin/env python3
import json
import os
import signal
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

BIN = Path(__file__).resolve().parents[1] / 'build'

class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zelx-cli-')
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'audit.db'
        self.run_ctl('policy', 'add', 'app', 'allow', '/home/app/**', 'always')

    def run_ctl(self, *args, ok=True):
        result = subprocess.run([str(BIN / 'zelxctl'), '--db', str(self.db), *args], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
        return result

    def test_list_revoke(self):
        self.run_ctl('policy', 'add', 'other', 'deny', '/secret', 'always')
        result = self.run_ctl('policy', 'list', 'app')
        self.assertIn('/home/app/**', result.stdout)
        self.assertNotIn('other', result.stdout)
        self.run_ctl('policy', 'revoke', 'app', 'filesystem')
        self.assertNotIn('/home/app/**', self.run_ctl('policy', 'list').stdout)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT app_id FROM revocations').fetchone()[0], 'app')

    def test_export_import_atomic(self):
        rules = json.loads(self.run_ctl('policy', 'export').stdout)
        self.assertEqual(rules['version'], 1)
        file = Path(self.temp.name) / 'backup.json'
        file.write_text(json.dumps(rules))
        self.run_ctl('policy', 'revoke', 'app', 'filesystem')
        self.run_ctl('policy', 'import', str(file))
        self.assertEqual(len(json.loads(self.run_ctl('policy', 'export').stdout)['rules']), 1)
        rules['rules'].append(dict(rules['rules'][0], decision='EXECUTE'))
        file.write_text(json.dumps(rules))
        self.run_ctl('policy', 'import', str(file), ok=False)
        self.assertEqual(len(json.loads(self.run_ctl('policy', 'export').stdout)['rules']), 1)
        for text in ['{} trailing', '{', json.dumps(dict(rules, version=2)), '{"version":1,"rules":[]} garbage']:
            file.write_text(text)
            self.run_ctl('policy', 'import', str(file), ok=False)

    def test_existing_c_database_is_preserved(self):
        self.db = Path(self.temp.name) / 'legacy.db'
        schema = Path(__file__).with_name('fixtures') / 'schema-v1-c.sql'
        with sqlite3.connect(self.db) as db:
            db.executescript(schema.read_text())
            db.execute("INSERT INTO rules VALUES(41,'legacy','filesystem','/legacy/**','ALLOW','ALWAYS',1234,'user')")
            db.execute("INSERT INTO events VALUES(51,1234,'legacy','legacy:42',42,'filesystem','/legacy/file','ALLOW',41,250)")
        self.assertIn('/legacy/**', self.run_ctl('policy', 'list', 'legacy').stdout)
        self.assertIn('/legacy/file', self.run_ctl('trace', 'legacy').stdout)
        exported = json.loads(self.run_ctl('policy', 'export').stdout)['rules'][0]
        self.assertEqual((exported['created_at'], exported['created_by']), (1234, 'user'))
        self.run_ctl('policy', 'add', 'new', 'deny', '/new/**', 'always')
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT id,created_at FROM rules WHERE app_id="legacy"').fetchone(), (41, 1234))
            self.assertEqual(db.execute('SELECT id,rule_id FROM events').fetchone(), (51, 41))
            self.assertEqual(db.execute('SELECT id FROM rules WHERE app_id="new"').fetchone()[0], 42)

    def test_import_rolls_back_database_errors(self):
        rule = json.loads(self.run_ctl('policy', 'export').stdout)['rules'][0]
        backup = {'version': 1, 'rules': [dict(rule, app_id='new'), dict(rule, app_id='blocked')]}
        file = Path(self.temp.name) / 'import.json'
        file.write_text(json.dumps(backup))
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TRIGGER refuse_import BEFORE INSERT ON rules WHEN NEW.app_id='blocked' BEGIN SELECT RAISE(ABORT,'blocked'); END")
        self.run_ctl('policy', 'import', str(file), ok=False)
        self.assertEqual([r['app_id'] for r in json.loads(self.run_ctl('policy', 'export').stdout)['rules']], ['app'])

    def test_legacy_non_utf8_audit_bytes_are_readable(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO events(ts,app_id,app_instance,pid,resource,target,decision) VALUES(1234,'legacy','legacy:42',42,'filesystem',CAST(? AS TEXT),'ALLOW')", (b'/old/secret\xff',))
        self.assertIn('/old/secret\\xff', self.run_ctl('trace', 'legacy').stdout)

    def test_unknown_database_version_is_untouched(self):
        with sqlite3.connect(self.db) as db:
            db.execute('PRAGMA user_version=99')
        self.run_ctl('policy', 'add', 'new', 'allow', '/new', 'always', ok=False)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 99)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rules').fetchone()[0], 1)

    def test_trace_time_sort_escape(self):
        now = int(time.time() * 1000)
        with sqlite3.connect(self.db) as db:
            for ts, app, target in [(now, 'app', '/new\x1b[2J'), (now-1000, 'app', '/recent'), (now-7200000, 'app', '/old'), (now, 'other', '/other')]:
                db.execute("INSERT INTO events(ts,app_id,app_instance,pid,resource,target,decision) VALUES(?,?,?,1,'filesystem',?,'ALLOW')", (ts, app, app+':1', target))
        result = self.run_ctl('trace', 'app', '--last', '1h').stdout
        self.assertNotIn('/old', result)
        self.assertNotIn('/other', result)
        self.assertLess(result.index('/recent'), result.index('/new'))
        self.assertIn('\\x1b', result)
        self.assertNotIn('\x1b', result)
        self.assertIn('/other', self.run_ctl('trace', '--all', '--last', '5m').stdout)
        self.assertIn('/recent', self.run_ctl('trace', '--last', '1h').stdout)
        for bad in ['0h', '-1h', '1x', '1hfoo', '999999999999999999999h']:
            self.run_ctl('trace', '--last', bad, ok=False)
        self.run_ctl('trace', 'app', '--all', ok=False)

    def test_launcher(self):
        result = subprocess.run([str(BIN / 'zelx-run'), '/usr/bin/printenv', 'ZELX_APP_ID'], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.stdout.strip(), 'printenv')
        self.assertEqual(subprocess.run([str(BIN / 'zelx-run'), '/usr/bin/false'], timeout=5).returncode, 1)
        result = subprocess.run([str(BIN / 'zelx-run')], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        args = ['spaces here', '$(literal)', '`literal`']
        result = subprocess.run([str(BIN / 'zelx-run'), '/usr/bin/printf', '%s\n', *args], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.stdout.splitlines(), args)
        result = subprocess.run([str(BIN / 'zelx-run'), '/usr/bin/printf', '%s', b'bytes\xff'], capture_output=True, timeout=5)
        self.assertEqual(result.stdout, b'bytes\xff')
        result = subprocess.run([str(BIN / 'zelx-run'), '/bin/sh', '-c', 'kill -TERM $$'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, -signal.SIGTERM)
        result = subprocess.run([str(BIN / 'zelx-run'), '/no/such/zelx-command'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 127)

    def test_bad_args_and_permissions(self):
        self.run_ctl('policy', 'add', 'app', 'maybe', '/x', 'always', ok=False)
        self.run_ctl('policy', 'add', 'app', 'allow', '/x', 'session', ok=False)
        self.run_ctl('policy', 'revoke', 'app', 'fake', ok=False)
        self.assertEqual(os.stat(self.db).st_mode & 0o777, 0o600)
        result = subprocess.run([str(BIN / 'zelxd'), '--timeout', '0'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)

if __name__ == '__main__':
    unittest.main(verbosity=2)
