"""Cross-process FIFO admission, with OS-lock leases rather than expiring PIDs.

Only capacity is recovered. No commands, transfer paths or replay instructions
are recorded here. Policies cannot be changed while an invocation is active.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..application.options import Options
from .filesystem import PinnedDirectory, private_directory, open_private_append

MAX_LEASES = 1024
_OWNED = set()
_HELD = contextvars.ContextVar('swassh_memory_reservation', default=None)


@contextmanager
def independent_invocation():
    """Give a public SDK operation its own reservation, restoring its caller.

    A task inherits context variables, but an independent operation must not
    borrow an enclosing session's capacity. Internal nested engine calls still
    share the reservation established within this scope.
    """
    token = _HELD.set(None)
    try:
        yield
    finally:
        _HELD.reset(token)


class FileLock:
    def __init__(self, path, *, directory=None):
        self.path = Path(path)
        self.stream = (open_private_append(path) if directory is None
                       else open_private_append(path, directory=directory))
        self.locked = False

    def acquire(self):
        try:
            if os.name == 'posix':
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                self.stream.seek(0)
                if not self.path.stat().st_size:
                    self.stream.write('0')
                    self.stream.flush()
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
        except (OSError, BlockingIOError):
            return False
        self.locked = True
        _OWNED.add(self.path)
        return True

    def close(self):
        if not self.stream.closed:
            try:
                if self.locked:
                    if os.name == 'posix':
                        import fcntl
                        fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
                    else:
                        import msvcrt
                        self.stream.seek(0)
                        msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                # A close error can follow descriptor release. Clear ownership
                # only after successful close or an observed closed stream;
                # otherwise keep the reservation and propagate the error.
                closed = False
                try:
                    self.stream.close()
                    closed = True
                finally:
                    if closed or self.stream.closed:
                        if self.locked:
                            _OWNED.discard(self.path)
                        self.locked = False


def specification(options: Options) -> dict:
    # One local-account pool across ALL targets, users and jump hosts. Multiple
    # source bastions require an external coordinator or OS/network quotas.
    scope = 'local-bastion'
    base = Path(options.budget_dir).expanduser() if options.budget_dir else Path.home() / '.swassh' / 'budgets'
    return {'directory': str(base / hashlib.sha256(scope.encode()).hexdigest()[:32]),
        'policy': [options.bastion_concurrency, options.bastion_connect_rate,
                   options.bastion_memory_mib * 1024**2, options.bastion_bandwidth_kib]}


class SharedBudget:
    """A bounded coordinator. All database use stays off the asyncio thread."""
    def __init__(self, spec):
        if (not isinstance(spec, dict) or set(spec) != {'directory', 'policy'}
                or not isinstance(spec['directory'], str) or not isinstance(spec['policy'], list)
                or len(spec['policy']) != 4):
            raise ValueError('invalid shared budget specification')
        c, r, m, b = spec['policy']
        if (type(c) is not int or not 1 <= c <= 10000 or type(m) is not int or not 72 * 1024**2 <= m <= 1048576 * 1024**2
                or type(b) is not int or not 1 <= b <= 2147483647 or isinstance(r, bool)
                or not isinstance(r, (int, float)) or not 0.1 <= r <= 1000):
            raise ValueError('invalid shared budget policy')
        self.directory = private_directory(Path(spec['directory']), tighten=True)
        self.policy = [c, float(r), m, b]
        path = self.directory / 'budget.sqlite3'
        # Create without following links before SQLite opens the trusted private path.
        with open_private_append(path):
            pass
        if path.stat().st_size > 8 * 1024**2:
            raise ValueError('shared budget database exceeds disk ceiling')
        self.db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        try:
            self._retry_busy(self._initialize)
        except BaseException:
            self.db.close()
            raise

    def _retry_busy(self, operation):
        """Retry a restartable local operation within a ten-second busy budget.

        Callers supply idempotent initialization or transaction acquisition.
        Only the Python retry loop waits: SQLite busy-handler sleeps can
        overshoot their requested duration on coarse platform clocks,
        creating convoys while queued peers compete with lease release.
        """
        deadline = time.monotonic() + 10
        self.db.execute('PRAGMA busy_timeout=0')
        try:
            while True:
                try:
                    return operation()
                except sqlite3.OperationalError as error:
                    if (getattr(error, 'sqlite_errorcode', 0) & 0xff != sqlite3.SQLITE_BUSY
                            or time.monotonic() >= deadline):
                        raise
                    time.sleep(0.01)
        finally:
            self.db.execute('PRAGMA busy_timeout=5000')

    def _initialize(self):
        self.db.execute('PRAGMA trusted_schema=OFF')
        self.db.execute('PRAGMA synchronous=FULL')
        page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
        self.db.execute('PRAGMA max_page_count=' + str(8 * 1024**2 // page_size))
        self.db.execute('PRAGMA cache_size=-2048')
        self.db.execute('PRAGMA journal_size_limit=8388608')
        self.db.execute('CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL, next REAL NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK(id=1), observed REAL NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS leases (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, active INTEGER NOT NULL, connections INTEGER NOT NULL, memory INTEGER NOT NULL, bandwidth INTEGER NOT NULL, parent_id TEXT)')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if 'parent_id' not in {row[1] for row in self.db.execute('PRAGMA table_info(leases)')}:
                self.db.execute('ALTER TABLE leases ADD COLUMN parent_id TEXT')
            self._recover()
            previous = self.db.execute('SELECT value,next FROM policy WHERE id=1').fetchone()
            if not self.db.execute('SELECT 1 FROM clock WHERE id=1').fetchone():
                # Legacy databases have no clock sample. Infer only a lower
                # bound from the largest legal reservation under the old policy;
                # never mistake a long, valid pacing interval for a reboot.
                old_policy = json.loads(previous[0]) if previous else self.policy
                observed = max(0.0, previous[1] - old_policy[0] / old_policy[1]) if previous else 0.0
                self.db.execute('INSERT INTO clock VALUES (1,?)', (observed,))
            policy = json.dumps(self.policy)
            if previous and json.loads(previous[0]) != self.policy:
                if self.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0]:
                    raise ValueError('shared budget policy differs from active invocations')
                self.db.execute('UPDATE policy SET value=? WHERE id=1', (policy,))
            elif not previous:
                self.db.execute('INSERT INTO policy VALUES (1,?,0)', (policy,))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def _recover(self):
        records = self.db.execute('SELECT id,kind,parent_id,active,connections,memory,bandwidth FROM leases LIMIT 1025').fetchall()
        # A damaged counter must never turn capacity accounting into an underflow.
        for identity, kind, parent, active, connections, memory, bandwidth in records:
            if (not isinstance(identity, str) or len(identity) != 32
                    or any(c not in '0123456789abcdef' for c in identity)
                    or kind not in {'memory', 'client', 'dependent'} or active not in (0, 1)
                    or any(type(value) is not int or value < 0 for value in (connections, memory, bandwidth))
                    # Recovery must also accept dead reservations from a larger
                    # previous policy before a cold reduction of its ceilings.
                    or connections > 10000 or memory > 1048576 * 1024**2 or bandwidth > 2147483647
                    or parent is not None and (not isinstance(parent, str) or len(parent) != 32
                        or any(c not in '0123456789abcdef' for c in parent))):
                raise ValueError('invalid shared budget lease counters or identity')
        rows = [(row[0], row[1], row[2]) for row in records]
        if len(rows) > MAX_LEASES:
            raise ValueError("shared budget contains too many leases")
        # Pin ancestry once for this serialized recovery, retaining every per-file
        # validation and OS lock probe while queued peers wait for the writer.
        with PinnedDirectory(self.directory) as directory:
            alive = set()
            for identity, _, _ in rows:
                if len(identity) != 32 or any(c not in '0123456789abcdef' for c in identity):
                    raise ValueError('invalid shared budget lease identity')
                lease_path = self.directory / (identity + '.lock')
                if lease_path in _OWNED:
                    # Some Unix ports emulate flock with process-owned fcntl locks.
                    # Never reopen/close a descriptor for a lock owned by this process.
                    alive.add(identity)
                    continue
                lock = FileLock(lease_path, directory=directory)
                try:
                    if not lock.acquire():
                        alive.add(identity)
                finally:
                    lock.close()
            # Keep an invocation's memory charged while ANY guardian/report worker
            # still owns a dependent lease, even if its CLI was killed first.
            parents = {parent for identity, _, parent in rows if identity in alive and parent}
            for identity, kind, _ in rows:
                if identity in alive or kind == 'memory' and identity in parents:
                    continue
                self.db.execute('DELETE FROM leases WHERE id=?', (identity,))
                (self.directory / (identity + '.lock')).unlink(missing_ok=True)
            known = {row[0] + '.lock' for row in self.db.execute('SELECT id FROM leases')}
            for index, path in enumerate(self.directory.glob('*.lock')):
                if index >= MAX_LEASES * 2:
                    raise ValueError('shared budget has too many orphan lock files')
                if path.name in known or path in _OWNED:
                    continue
                lock = FileLock(path)
                try:
                    if lock.acquire():
                        lock.close()
                        path.unlink(missing_ok=True)
                finally:
                    lock.close()

    def ticket(self, *, connections=0, memory=0, bandwidth=0, parent=None, activate=False):
        """Publish a lease; optionally attempt FIFO admission in that commit."""
        if type(activate) is not bool:
            raise ValueError('activation must be boolean')
        amounts = (connections, memory, bandwidth)
        if any(type(v) is not int or v < 0 for v in amounts) or not any(amounts) and parent is None:
            raise ValueError('invalid budget reservation')
        if connections > self.policy[0] or memory > self.policy[2] or bandwidth > self.policy[3]:
            raise ValueError('reservation exceeds shared bastion policy')
        identity = uuid.uuid4().hex
        lock = None
        try:
            self._retry_busy(lambda: self.db.execute('BEGIN IMMEDIATE'))
            self._check_policy()
            # Publish the lock and its row under the same coordinator transaction.
            # An orphan scanner cannot unlink it between open and lock acquisition.
            lock = FileLock(self.directory / (identity + '.lock'))
            if not lock.acquire():
                raise RuntimeError('cannot own shared lease')
            self._recover()
            if self.db.execute('SELECT COUNT(*) FROM leases').fetchone()[0] >= MAX_LEASES:
                raise ValueError('shared budget queue is full')
            if parent is not None:
                owner = self.db.execute("SELECT id FROM leases WHERE id=? AND kind='memory' AND active=1", (parent,)).fetchone()
                if owner is None:
                    raise ValueError('invocation memory reservation unavailable')
            dependent = not any(amounts)
            self.db.execute('INSERT INTO leases(id,kind,active,connections,memory,bandwidth,parent_id) VALUES (?,?,?,?,?,?,?)',
                (identity, 'dependent' if dependent else 'client' if connections else 'memory',
                 int(dependent), *amounts, parent))
            lease = Lease(self,identity,lock)
            if activate:
                # The same serialized predicate as poll(), before publication.
                # Queue order, rate, memory and policy are checked together;
                # a queued request still returns an ordinary inactive lease.
                lease._admit()
            self.db.execute('COMMIT')
        except BaseException:
            try:
                if lock is not None:
                    lock.close()
                    lock.path.unlink(missing_ok=True)
            finally:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
            raise
        return lease

    def _check_policy(self):
        """Reject stale idle handles after another process changes the policy."""
        row = self.db.execute('SELECT value FROM policy WHERE id=1').fetchone()
        if row is None or json.loads(row[0]) != self.policy:
            raise ValueError('shared budget policy changed; reopen the coordinator')

    def close(self):
        self.db.close()


class Lease:
    def __init__(self, pool, identity, lock):
        self.pool, self.identity, self.lock = pool, identity, lock
        self.started = time.monotonic()
        self.wait_seconds = 0.0
        self._not_before = None

    @property
    def retry_after(self):
        """Bounded wait advice, never permission to bypass the next poll.

        Only a capacity-fitting FIFO head can use its validated rate deadline.
        Capacity/queue/storage waits retain the conservative 50 ms cadence.
        Expired advice still requires a new policy/lock/transaction check.
        """
        if self._not_before is None:
            return 0.05
        return max(0.001,min(0.05,self._not_before-time.monotonic()))

    def poll(self):
        """Attempt admission without sleeping inside SQLite while peers release slots."""
        db, policy = self.pool.db, self.pool.policy
        self._not_before = None
        # A pending poll must yield to the caller, not join SQLite's five-second
        # busy-wait convoy. Initialization and release keep their bounded retry
        # policy; restore this connection's previous setting on every exit.
        previous_timeout = db.execute('PRAGMA busy_timeout').fetchone()[0]
        db.execute('PRAGMA busy_timeout=0')
        try:
            try:
                db.execute('BEGIN IMMEDIATE')
            except sqlite3.OperationalError as exc:
                # Contention is a pending admission, not a failed remote command.
                # Only BUSY is retryable here; malformed/failed storage stays fatal.
                if getattr(exc, 'sqlite_errorcode', 0) & 0xff == sqlite3.SQLITE_BUSY:
                    return False
                raise
            try:
                self.pool._check_policy()
                self.pool._recover()
                admitted=self._admit()
                db.execute('COMMIT')
                return admitted
            except BaseException as exc:
                if db.in_transaction:
                    db.execute('ROLLBACK')
                # A reader can also delay the final commit. Since the reservation
                # was rolled back, it is safe to remain queued without consuming it.
                if isinstance(exc, sqlite3.OperationalError) and getattr(exc, 'sqlite_errorcode', 0) & 0xff == sqlite3.SQLITE_BUSY:
                    return False
                raise
        finally:
            db.execute('PRAGMA busy_timeout=' + str(previous_timeout))

    def _admit(self):
        """Evaluate admission inside the caller's existing write transaction."""
        db, policy = self.pool.db, self.pool.policy
        if not db.in_transaction:
            raise RuntimeError('admission requires an active transaction')
        # This method intentionally owns no commit or rollback: a lease cannot
        # become visible before both its OS lock and all counters are committed.
        row = db.execute('SELECT seq,kind,active,connections,memory,bandwidth FROM leases WHERE id=?', (self.identity,)).fetchone()
        if row is None:
            raise RuntimeError('owned lease vanished')
        seq, kind, active, connections, memory, bandwidth = row
        if active:
            return True
        first = db.execute('SELECT MIN(seq) FROM leases WHERE active=0 AND kind=?', (kind,)).fetchone()[0]
        used = db.execute('SELECT COALESCE(SUM(connections),0),COALESCE(SUM(memory),0),COALESCE(SUM(bandwidth),0) FROM leases WHERE active=1').fetchone()
        next_start = db.execute('SELECT next FROM policy WHERE id=1').fetchone()[0]
        now = time.monotonic()
        observed = db.execute('SELECT observed FROM clock WHERE id=1').fetchone()[0]
        # Only a backwards monotonic clock indicates an epoch change.
        # Long reservations and idle policy changes retain their deadlines.
        if now < observed:
            if any(used):
                raise ValueError('shared budget clock regressed with active reservations')
            next_start = now
            db.execute('UPDATE policy SET next=? WHERE id=1', (now,))
        db.execute('UPDATE clock SET observed=? WHERE id=1', (now,))
        fits = all(a + b <= cap for a, b, cap in zip(used, (connections, memory, bandwidth), (policy[0], policy[2], policy[3])))
        self._not_before = next_start if first == seq and fits and connections else None
        admitted = first == seq and fits and (not connections or now >= next_start)
        if admitted:
            db.execute('UPDATE leases SET active=1 WHERE id=?', (self.identity,))
            if connections:
                db.execute('UPDATE policy SET next=? WHERE id=1', (now + connections / policy[1],))
            self.wait_seconds = now - self.started
        return admitted

    def close(self):
        db = self.pool.db
        try:
            self.pool._retry_busy(lambda: db.execute('BEGIN IMMEDIATE'))
            self.pool._recover()
            db.execute('DELETE FROM leases WHERE id=? AND NOT EXISTS (SELECT 1 FROM leases WHERE parent_id=?)',
                (self.identity, self.identity))
            retained = db.execute('SELECT 1 FROM leases WHERE id=?', (self.identity,)).fetchone()
            self.lock.close()
            if not retained:
                self.lock.path.unlink(missing_ok=True)
            db.execute('COMMIT')
        except BaseException:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            self.lock.close()


def current_reservation():
    held = _HELD.get()
    return held[1] if held else None


async def _io(call):
    import asyncio
    from .lifecycle import finish_task
    from ..application.task_ownership import wait_owned
    task = asyncio.create_task(asyncio.to_thread(call))
    try:
        return await wait_owned(task)
    except asyncio.CancelledError:
        await finish_task(task)
        raise


def _close_reservation(pool, lease):
    """Always close SQLite, even when releasing the lease fails on storage I/O."""
    try:
        lease.close()
    finally:
        pool.close()


@asynccontextmanager
async def invocation_budget(options):
    # SharedBudget is also used by synchronous guardian/relay children. Keep
    # their cold startup independent of the application's asyncio stack.
    import asyncio
    from .lifecycle import finish_task
    from ..application.task_ownership import wait_owned
    spec = specification(options)
    key = spec['directory']
    if _HELD.get() and _HELD.get()[0] == key:
        yield
        return
    # SQLite calls are serialized and shielded; no access overlaps cancellation cleanup.
    def reserve():
        pool = SharedBudget(spec)
        try:
            return pool, pool.ticket(memory=(options.memory_budget_mib + 64) * 1024**2)
        except BaseException:
            pool.close()
            raise
    task = asyncio.create_task(asyncio.to_thread(reserve))
    try:
        pool, lease = await wait_owned(task)
    except asyncio.CancelledError:
        pool, lease = await finish_task(task)
        await _io(lambda: _close_reservation(pool, lease))
        raise
    token = None
    try:
        while not await _io(lease.poll):
            await asyncio.sleep(0.05)
        token = _HELD.set((key, lease.identity))
        yield
    finally:
        if token is not None:
            _HELD.reset(token)
        await _io(lambda: _close_reservation(pool, lease))


@contextmanager
def cli_invocation_budget(options):
    """Reserve before reading a CLI inventory; asyncio.run inherits this context."""
    spec = specification(options)
    if _HELD.get() and _HELD.get()[0] == spec['directory']:
        yield
        return
    pool = SharedBudget(spec)
    lease = token = None
    try:
        lease = pool.ticket(memory=(options.memory_budget_mib + 64) * 1024**2)
        while not lease.poll():
            time.sleep(0.05)
        token = _HELD.set((spec['directory'], lease.identity))
        yield
    finally:
        if token is not None:
            _HELD.reset(token)
        try:
            if lease is not None:
                lease.close()
        finally:
            pool.close()


