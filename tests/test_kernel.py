#!/usr/bin/env python3
"""Real fanotify tests. Requires CAP_SYS_ADMIN in the initial user namespace.
Only disposable temporary paths are gated. Never monitors the user's home.
FAN_CLASS_CONTENT + FAN_DENY returns EPERM; both transports must agree exactly.
"""
import ctypes
import errno
import os
from pathlib import Path
import select
import socket
import struct
import sqlite3
import subprocess
import tempfile
import time
import unittest

SIMULATED = os.environ.get("ZELX_SIMULATED") == "1"

BIN = Path(__file__).resolve().parents[1] / 'build'

def capability():
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.fanotify_init(0x4 | 0x1 | 0x2, os.O_RDONLY | os.O_CLOEXEC)
    if fd < 0:
        return os.strerror(ctypes.get_errno())
    os.close(fd)
    return None

class KernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        problem = None if SIMULATED else capability()
        if problem:
            raise RuntimeError('fanotify permission group unavailable (run privileged): ' + problem)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zelx-kernel-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.watch = self.root / 'protected'
        self.watch.mkdir()
        (self.watch / 'nested').mkdir()
        self.target = self.watch / 'nested' / 'secret'
        self.target.write_text('private')
        self.db = self.root / 'audit.db'
        self.master, self.slave = os.openpty()
        os.set_blocking(self.master, False)
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)
        self.daemon = None
        self.children = []
        self.env = os.environ.copy()
        if SIMULATED:
            self.env["ZELX_TEST_SOCKET"] = str(self.root / "fan.sock")
        self.daemon_env = self.env.copy()
        if SIMULATED:
            self.daemon_env["LD_PRELOAD"] = str(BIN / "fake_fanotify.so")
        self.addCleanup(self.cleanup_processes)

    def cleanup_processes(self):
        if self.daemon and self.daemon.poll() is None:
            self.daemon.terminate()
            self.daemon.communicate(timeout=5)
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)

    def start(self, audit=False, extra=()):
        if SIMULATED:
            (self.root / "fan.sock").unlink(missing_ok=True)
        args = [str(BIN / 'zelxd'), '--db', str(self.db), '--watch', str(self.watch),
                '--tty', os.ttyname(self.slave), '--timeout', '1']
        if audit:
            args += ['--audit-only']
        args += list(extra)
        self.daemon = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=self.daemon_env)
        ready = select.select([self.daemon.stderr], [], [], 5)[0]
        self.assertTrue(ready, 'daemon did not become ready')
        line = self.daemon.stderr.readline()
        self.assertIn(b'zelxd ready', line, line.decode())

    def stop(self):
        self.daemon.terminate()
        _, err = self.daemon.communicate(timeout=5)
        self.assertEqual(self.daemon.returncode, 0, err.decode())
        self.daemon = None

    def opening(self, target=None):
        child = subprocess.Popen([str(BIN / 'zelx-run'), str(BIN / 'zelx-open'), str(target or self.target)], env=self.env)
        self.children.append(child)
        return child

    def assert_open_result(self, child, expected):
        actual = child.wait(timeout=3)
        if actual == expected:
            return
        details = []
        try:
            with sqlite3.connect(self.db, timeout=1) as db:
                for label, query in [
                    ('rules', 'SELECT id,app_id,resource,target_glob,decision FROM rules'),
                    ('revocations', 'SELECT * FROM revocations'),
                    ('revision', 'SELECT * FROM policy_state'),
                    ('recent_events', 'SELECT app_id,target,decision,rule_id FROM events ORDER BY id DESC LIMIT 8'),
                ]:
                    details.append(f'{label}={db.execute(query).fetchall()!r}')
        except sqlite3.Error as error:
            details.append(f'database diagnostic failed: {error}')
        if self.daemon:
            status = self.daemon.poll()
            details.append(f'daemon_exit={status!r}')
            if status is not None:
                _, errors = self.daemon.communicate(timeout=3)
                details.append(f'daemon_stderr={errors.decode(errors="backslashreplace")!r}')
            else:
                descriptors = Path(f'/proc/{self.daemon.pid}/fd')
                try:
                    details.append(f'daemon_fds={[(p.name, os.readlink(p)) for p in descriptors.iterdir()]!r}')
                except OSError as error:
                    details.append(f'descriptor diagnostic failed: {error}')
                if select.select([self.daemon.stderr], [], [], 0)[0]:
                    errors = os.read(self.daemon.stderr.fileno(), 65536)
                    details.append(f'daemon_stderr={errors.decode(errors="backslashreplace")!r}')
        self.fail(f'open returned {actual}, expected {expected}; ' + '; '.join(details))

    def prompt(self):
        text = b''
        end = time.monotonic() + 3
        while b'Choice ' not in text and time.monotonic() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                text += os.read(self.master, 65536)
        self.assertIn(b'ZELX PERMISSION REQUEST', text)
        self.assertIn(str(self.target).encode(), text)
        return text

    def choose(self, choice):
        self.prompt()
        os.write(self.master, str(choice).encode() + b'\n')

    def events(self):
        with sqlite3.connect(self.db) as db:
            return db.execute('SELECT app_id,target,decision,rule_id FROM events ORDER BY id').fetchall()

    def test_audit_nested_self_deadlock_and_filter(self):
        self.db = self.watch / 'audit.db'  # forces SQLite opens on the marked FS
        self.start(audit=True)
        if SIMULATED:
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                client.connect(self.env['ZELX_TEST_SOCKET'])
                client.sendall(struct.pack('=i4096s', self.daemon.pid, os.fsencode(self.target)))
                self.assertEqual(struct.unpack('=I', client.recv(4))[0], 1)
        self.assert_open_result(self.opening(), 0)
        outside = self.root / 'outside'
        outside.write_text('outside')
        self.assertEqual(self.opening(outside).wait(timeout=3), 0)
        self.stop()
        rows = self.events()
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0][:3], ('zelx-open', str(self.target), 'ALLOW'))
        self.assertNotIn('zelxd', [r[0] for r in rows])

    def test_non_utf8_paths_never_match_lossy_grants(self):
        path = os.fsdecode(os.fsencode(self.watch) + b'/secret\xff')
        with open(path, 'w') as file:
            file.write('private')
        subprocess.run([str(BIN / 'zelxctl'), '--db', str(self.db), 'policy', 'add', 'zelx-open', 'allow', str(self.watch) + '/**', 'always'], check=True, timeout=3)
        self.start()
        self.assert_open_result(self.opening(path), errno.EPERM)
        self.stop()
        rows = self.events()
        self.assertEqual(rows[0][2], 'DENY')
        self.assertIn('\\xff', rows[0][1])
        self.assertIsNone(rows[0][3])
        self.start(audit=True)
        self.assert_open_result(self.opening(path), 0)
        self.stop()
        self.assertEqual(self.events()[1][2], 'ALLOW')

    def test_existing_c_database_rules_apply(self):
        schema = Path(__file__).with_name('fixtures') / 'schema-v1-c.sql'
        with sqlite3.connect(self.db) as db:
            db.executescript(schema.read_text())
            db.execute("INSERT INTO rules VALUES(41,'zelx-open','filesystem',?,'ALLOW','ALWAYS',1234,'user')", (str(self.target),))
        self.db.chmod(0o600)
        self.start()
        self.assert_open_result(self.opening(), 0)
        self.stop()
        self.assertEqual(self.events()[0][3], 41)

    def test_deny_once_and_always_persistence(self):
        self.start()
        child = self.opening(); self.choose(3)
        self.assert_open_result(child, errno.EPERM)
        child = self.opening(); self.choose(2)
        self.assert_open_result(child, 0)
        self.assert_open_result(self.opening(), 0)
        self.stop(); self.start()
        self.assert_open_result(self.opening(), 0)
        self.stop()
        rows = self.events()
        self.assertEqual([r[2] for r in rows], ['PROMPT_DENY', 'PROMPT_ALLOW', 'ALLOW', 'ALLOW'])
        self.assertTrue(rows[1][3])

    def test_session_restart_and_live_revoke(self):
        self.start()
        child = self.opening(); self.choose(5)
        self.assert_open_result(child, 0)
        self.assert_open_result(self.opening(), 0)
        subprocess.run([str(BIN / 'zelxctl'), '--db', str(self.db), 'policy', 'revoke', 'zelx-open', 'filesystem'], check=True, timeout=3)
        child = self.opening(); self.choose(5)
        self.assert_open_result(child, 0)
        self.stop(); self.start()
        child = self.opening(); self.choose(4)
        self.assert_open_result(child, errno.EPERM)
        self.assert_open_result(self.opening(), errno.EPERM)
        self.stop()

    @unittest.skipIf(SIMULATED, 'mount coverage requires real kernel privileges')
    def test_nested_filesystem(self):
        mountpoint = self.watch / 'mount'
        mountpoint.mkdir()
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=1m', 'tmpfs', str(mountpoint)], check=True, timeout=5)
        try:
            self.target = mountpoint / 'secret'
            self.target.write_text('private')
            self.start()
            child = self.opening(); self.choose(3)
            self.assert_open_result(child, errno.EPERM)
            self.stop()
        finally:
            self.cleanup_processes()
            subprocess.run(['umount', str(mountpoint)], check=True, timeout=5)

    def test_late_input_cannot_save_or_approve_the_next_request(self):
        self.start()
        child = self.opening(); self.prompt()
        self.assert_open_result(child, errno.EPERM)
        os.write(self.master, b'2\n')
        child = self.opening(); self.choose(3)
        self.assert_open_result(child, errno.EPERM)
        self.stop()
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rules').fetchone()[0], 0)

    def test_audit_failure_stops_the_daemon(self):
        subprocess.run([str(BIN / 'zelxctl'), '--db', str(self.db), 'policy', 'add', 'zelx-open', 'allow', str(self.watch) + '/**', 'always'], check=True, timeout=3)
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TRIGGER refuse_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
        self.start(audit=True)
        self.assert_open_result(self.opening(), 0)
        _, errors = self.daemon.communicate(timeout=3)
        self.assertEqual(self.daemon.returncode, 1, errors.decode())
        self.assertIn(b'AUDIT WRITE FAILED', errors)
        self.daemon = None

    def test_queued_timeouts(self):
        self.start()
        begin = time.monotonic()
        children = [self.opening() for _ in range(4)]
        for child in children:
            self.assert_open_result(child, errno.EPERM)
        self.assertLess(time.monotonic() - begin, 2.5)
        self.stop()
        self.assertEqual(len(self.events()), 4)

    def test_pending_shutdown_and_crash(self):
        self.start()
        child = self.opening(); self.prompt()
        self.stop()
        self.assert_open_result(child, errno.EPERM)
        self.start()
        child = self.opening(); self.prompt()
        self.daemon.kill(); self.daemon.communicate(timeout=3)
        self.daemon = None
        self.assert_open_result(child, 0)  # kernel fail-open on last group fd close

    def test_explicit_exemption(self):
        child = subprocess.Popen([str(BIN / 'zelx-open'), '--wait', str(self.target)], stdin=subprocess.PIPE, env=self.env)
        self.children.append(child)
        self.start(extra=['--exempt-pid', str(child.pid)])
        child.stdin.write(b'1'); child.stdin.close()
        self.assert_open_result(child, 0)
        self.stop()
        self.assertEqual(self.events(), [])

    def test_no_terminal_and_external_rule_updates(self):
        # No CLI input => deny immediately, rather than waiting forever.
        self.daemon = subprocess.Popen([str(BIN / 'zelxd'), '--db', str(self.db), '--watch', str(self.watch)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=self.daemon_env)
        self.assertTrue(select.select([self.daemon.stderr], [], [], 5)[0])
        self.assertIn(b'zelxd ready', self.daemon.stderr.readline())
        self.assert_open_result(self.opening(), errno.EPERM)
        sidecars = [Path(str(self.db) + suffix) for suffix in ('', '-wal', '-shm')]
        inodes = [path.stat().st_ino for path in sidecars]
        for _ in range(10):
            # Exercise opens on the broad filesystem mark, even though storage
            # is outside --watch. Closing an unignored event fd for these files
            # releases the daemon's SQLite POSIX locks across all its threads.
            for path in sidecars:
                if SIMULATED:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                        client.settimeout(3)
                        client.connect(self.env['ZELX_TEST_SOCKET'])
                        client.sendall(struct.pack('=i4096s', os.getpid(), os.fsencode(path)))
                        self.assertEqual(struct.unpack('=I', client.recv(4))[0], 1)
                else:
                    with open(path, 'rb') as file:
                        file.read(1)
            subprocess.run([str(BIN / 'zelxctl'), '--db', str(self.db), 'policy', 'add', 'zelx-open', 'allow', str(self.watch) + '/**', 'always'], check=True, timeout=3)
            self.assert_open_result(self.opening(), 0)
            self.assert_open_result(self.opening(), 0)  # warm the allow cache
            subprocess.run([str(BIN / 'zelxctl'), '--db', str(self.db), 'policy', 'revoke', 'zelx-open', 'filesystem'], check=True, timeout=3)
            self.assert_open_result(self.opening(), errno.EPERM)
            self.assertEqual([path.stat().st_ino for path in sidecars], inodes)
        self.stop()
        self.assertEqual([row[2] for row in self.events()],
                         ['PROMPT_DENY'] + ['ALLOW', 'ALLOW', 'PROMPT_DENY'] * 10)

if __name__ == '__main__':
    if SIMULATED:
        print('SIMULATED transport: kernel interception and self-open generation are NOT verified', flush=True)
    unittest.main(verbosity=2)
