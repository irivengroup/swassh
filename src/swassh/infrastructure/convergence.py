"""Private SQLite intents and OS locks for desired-state mutations."""

from ..application.task_ownership import wait_owned
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import sqlite3

from .audit import _WriterLock
from .bastion import _io, specification
from .database.migration.convergence_v1 import ConvergenceSchema, APPLICATION_ID
from .execution_input import InputSnapshot
from .filesystem import open_private_append, private_directory
from .inventory import _unique_object, _invalid_constant
from .lifecycle import finish_task
from ..domain.convergence import DesiredState


def load_desired_state(path) -> DesiredState:
    """Load a bounded strict JSON specification without exposing its contents."""
    try:
        raw = InputSnapshot.read(path, 512 * 1024)
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
        return DesiredState.from_dict(data)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('invalid desired-state JSON specification') from None


class _Lease:
    def __init__(self, journal, key, pending):
        self.journal, self.key, self.pending = journal, key, pending

    async def applying(self):
        await self.journal._state(self.key, 'applying')

    async def verified(self):
        await self.journal._state(self.key, 'verified')

    async def blocked(self):
        await self.journal._state(self.key, 'blocked')


class SQLiteConvergenceJournal:
    """Lazy, bounded journal shared by a transport's concurrent host workers.

    Rows contain only a SHA-256 identity and a state, never a command or secret.
    Fixed per-identity lock markers remain on disk to avoid inode replacement
    races. The capacity check precedes marker creation, bounding their count.
    Native storage failures always stop admission; pending intents survive them.
    """

    def __init__(self, options, *, directory=None, max_records=100000):
        if type(max_records) is not int or not 1 <= max_records <= 100000:
            raise ValueError('desired-state capacity must be 1..100000')
        self.directory = Path(directory) if directory is not None else Path(specification(options)['directory']) / 'convergence'
        self.max_records = max_records
        self.db = None
        self.lock = asyncio.Lock()
        self.active = 0
        self.closed = False

    def _open(self):
        self.directory = private_directory(self.directory.expanduser().absolute(), tighten=True)
        self.locks = private_directory(self.directory / 'locks', tighten=True)
        path = self.directory / 'intents.sqlite'
        with open_private_append(path):
            pass
        if path.stat().st_size > 32 * 1024**2:
            raise ValueError('desired-state database exceeds its capacity')
        db = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=3,
                             isolation_level=None, check_same_thread=False)
        try:
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=EXTRA')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA cache_size=-512')
            size = db.execute('PRAGMA page_size').fetchone()[0]
            db.execute('PRAGMA max_page_count=' + str(32 * 1024**2 // size))
            db.execute('BEGIN IMMEDIATE')
            ConvergenceSchema.up(db)
            count = db.execute('SELECT records FROM capacity WHERE id=1').fetchone()
            if (count is None or type(count[0]) is not int or not 0 <= count[0] <= self.max_records
                    or db.execute('SELECT count(*) FROM records').fetchone()[0] != count[0]
                    or db.execute("SELECT 1 FROM records WHERE state NOT IN ('checking','applying','verified','blocked') OR typeof(id)!='text' OR length(id)!=64 OR id GLOB '*[^0-9a-f]*' LIMIT 1").fetchone()):
                raise ValueError('invalid desired-state journal counters or records')
            db.commit()
            self.schema_version = db.execute('PRAGMA schema_version').fetchone()[0]
            self.db = db
        except BaseException:
            try:
                db.rollback()
            finally:
                db.close()
            raise

    async def _call(self, function, *args):
        async with self.lock:
            if self.closed:
                raise RuntimeError('desired-state journal is closed')
            if self.db is None:
                await _io(self._open)
            return await _io(lambda: function(*args))

    def _transaction(self, key, state=None):
        db = self.db
        db.execute('BEGIN IMMEDIATE')
        try:
            if (db.execute('PRAGMA schema_version').fetchone()[0] != self.schema_version
                    or db.execute('PRAGMA user_version').fetchone()[0] != 1
                    or db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID):
                raise ValueError('desired-state schema changed while open')
            row = db.execute('SELECT state FROM records WHERE id=?', (key,)).fetchone()
            if row is None:
                if state is not None:
                    raise ValueError('desired-state owned intent disappeared')
                count = db.execute('SELECT records FROM capacity WHERE id=1').fetchone()
                if count is None or type(count[0]) is not int or not 0 <= count[0] < self.max_records:
                    raise ValueError('desired-state journal is full or invalid; preserve and inspect its records')
                db.execute("INSERT INTO records VALUES (?, 'checking')", (key,))
                db.execute('UPDATE capacity SET records=records+1 WHERE id=1')
                row = ('checking',)
            if row[0] not in ('checking', 'applying', 'verified', 'blocked'):
                raise ValueError('invalid desired-state intent')
            if state is not None:
                db.execute('UPDATE records SET state=? WHERE id=?', (state, key))
            db.commit()
            return row[0]
        except BaseException:
            db.rollback()
            raise

    async def _state(self, key, state):
        await self._call(self._transaction, key, state)

    @asynccontextmanager
    async def scope(self, host, action):
        key = hashlib.sha256((action.digest + '\0' + host.target).encode()).hexdigest()
        # Reserve a bounded row before creating a permanent lock marker.
        await self._call(self._transaction, key)
        try:
            creating = asyncio.create_task(asyncio.to_thread(_WriterLock, self.locks / key))
            try:
                lock = await wait_owned(creating)
            except asyncio.CancelledError:
                lock = await finish_task(creating)
                await _io(lock.close)
                raise
        except OSError:
            raise ValueError('desired-state operation already active or lock unavailable') from None
        self.active += 1
        try:
            # Re-read under the OS lock: another process may have finished
            # between row allocation and acquisition of this identity.
            state = await self._call(self._transaction, key)
            yield _Lease(self, key, state in ('applying', 'blocked'))
        finally:
            try:
                await _io(lock.close)
            finally:
                self.active -= 1

    async def aclose(self):
        async with self.lock:
            if self.active:
                raise RuntimeError('cannot close a journal with active operations')
            if not self.closed:
                self.closed = True
                if self.db is not None:
                    await _io(self.db.close)
