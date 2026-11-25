"""Private interprocess byte shaping; one shared bucket for transmit and receive."""
from pathlib import Path
from contextlib import contextmanager
import sqlite3
import threading
import time
import stat
import uuid

from ..domain.credit_state import _CreditState
from .bastion import SharedBudget, FileLock, _OWNED, MAX_LEASES
from .database.migration.encrypted_bytes_v2 import EncryptedByteSchema
from .filesystem import open_private_append
from .filesystem import is_link

APPLICATION_ID=0x53574257


def __getattr__(name):
    """Preserve prior model aliases without loading metadata in the guardian."""
    if name=='CreditPool':
        from ..domain.byte_credits import CreditPool
        return CreditPool
    if name=='ByteWindow':
        from ..domain.bandwidth import ByteWindow
        return ByteWindow
    raise AttributeError(name)


class SQLiteByteBudget:
    """Bounded byte counters below the existing local-account budget root.

    The normal guardian owns connection/memory admission. This adapter validates
    the same active policy, then charges encrypted payload bytes transactionally.
    It never reserves future tokens, so a dead client cannot leave a long debt.
    """
    def __init__(self,spec,*,coordinator=None):
        owned=coordinator is None
        if owned:
            coordinator=SharedBudget(spec)
        elif not isinstance(coordinator,SharedBudget):
            raise ValueError('encrypted-byte coordinator must be validated')
        else:
            coordinator._check_policy()
        try:
            self.rate=coordinator.policy[3]*1024
            path=Path(coordinator.directory)/'encrypted-bytes.sqlite'
            with open_private_append(path):
                pass
        finally:
            if owned:
                coordinator.close()
        if path.stat().st_size>1024**2:
            raise ValueError('encrypted-byte database exceeds 1 MiB')
        self.lock=threading.RLock()
        self.credit_owner=None
        self.remaining=self.pending=self.spent=0
        self.closed=False
        self.credit_failed=False
        self.path=path
        self.mutex=path.with_suffix('.mutex')
        with self._serialized():
            for suffix in ('-wal','-shm','-journal'):
                sidecar=Path(str(path)+suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    info=sidecar.lstat()
                    if is_link(info) or not stat.S_ISREG(info.st_mode) or info.st_size>2*1024**2:
                        raise ValueError('invalid encrypted-byte sidecar')
            self._open(path)

    def _open(self,path):
        """Open under the OS mutex, including implicit SQLite recovery."""
        self.db=sqlite3.connect(path.as_uri()+'?mode=rw',uri=True,timeout=3,
                                isolation_level=None,check_same_thread=False)
        try:
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA synchronous=EXTRA')
            # Commit each debit durably with one WAL synchronization. Every
            # writer, checkpoint and close also owns the same OS mutex. This
            # prevents concurrent WAL resets/checkpoints, including on older
            # SQLite versions affected by the documented WAL-reset race.
            if self.db.execute('PRAGMA journal_mode=WAL').fetchone()[0]!='wal':
                raise ValueError('encrypted-byte durable WAL unavailable')
            self.db.execute('PRAGMA wal_autocheckpoint=0')
            self.db.execute('PRAGMA journal_size_limit=65536')
            self.db.execute('PRAGMA cache_size=-256')
            size=self.db.execute('PRAGMA page_size').fetchone()[0]
            self.db.execute('PRAGMA max_page_count='+str(1024**2//size))
            self._checkpoint()
            self.db.execute('BEGIN IMMEDIATE')
            original_version=self.db.execute('PRAGMA user_version').fetchone()[0]
            EncryptedByteSchema.up(self.db)
            row=self.db.execute('SELECT rate,credits,observed FROM bucket WHERE id=1').fetchone()
            leases=self._owners()
            if row:
                _CreditState(*row,sum(amount for _,amount in leases))
            if row is None:
                if original_version!=0 or leases:
                    raise ValueError('encrypted-byte counters missing from known database')
                self.db.execute('INSERT INTO bucket VALUES (1,?,?,?)',
                    (self.rate,min(16384,self.rate)*1000000000,time.monotonic_ns()))
            elif row[0]!=self.rate:
                # SharedBudget already refused changing a policy with live
                # invocations. A cold policy change starts without free credit.
                self.db.execute('UPDATE bucket SET rate=?,credits=0,observed=? WHERE id=1',
                                (self.rate,time.monotonic_ns()))
                for identity,_ in leases:
                    path=self.path.parent/('credit-'+identity+'.mutex')
                    owner=FileLock(path)
                    try:
                        if path in _OWNED or not owner.acquire():
                            raise ValueError('encrypted-byte policy changed with outstanding owners')
                    finally:owner.close()
                    self.db.execute('DELETE FROM byte_leases WHERE id=?',(identity,))
                    path.unlink(missing_ok=True)
            known={identity for identity,_ in self._owners()}
            for index,path in enumerate(self.path.parent.glob('credit-*.mutex')):
                if index>=MAX_LEASES*2:raise ValueError('too many encrypted-byte orphan locks')
                if path.name[7:-6] in known or path in _OWNED:continue
                owner=FileLock(path)
                try:
                    if owner.acquire():
                        owner.close();path.unlink(missing_ok=True)
                finally:owner.close()
            self.db.commit()
            self.schema_version=self.db.execute('PRAGMA schema_version').fetchone()[0]
        except BaseException:
            try:
                self.db.rollback()
            finally:
                self.db.close()
            raise

    @property
    def chunk_size(self):
        return min(16384,self.rate)

    def reserve(self,count,*,now=None):
        """Return seconds to wait; callers must retry before transmitting bytes."""
        with self._serialized():
            self._checkpoint()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                window=self._window(time.monotonic_ns() if now is None else now)
                window,wait=window.debit(count)
                self._save(window)
                self.db.commit()
                return wait/1000000000
            except BaseException:
                self.db.rollback()
                raise

    def _window(self,now):
        if (self.db.execute('PRAGMA schema_version').fetchone()[0]!=self.schema_version
                or self.db.execute('PRAGMA user_version').fetchone()[0]!=2
                or self.db.execute('PRAGMA application_id').fetchone()[0]!=APPLICATION_ID):
            raise ValueError('encrypted-byte schema changed while open')
        row=self.db.execute('SELECT rate,credits,observed FROM bucket WHERE id=1').fetchone()
        if row is None or row[0]!=self.rate:
            raise ValueError('encrypted-byte policy or counters changed')
        leases=self._owners()
        window=_CreditState(*row,sum(amount for _,amount in leases)).refill(now)
        for identity,amount in leases:
            path=self.path.parent/('credit-'+identity+'.mutex')
            if path in _OWNED:continue
            owner=FileLock(path)
            try:
                dead=owner.acquire()
            finally:owner.close()
            if dead:
                self.db.execute('DELETE FROM byte_leases WHERE id=?',(identity,))
                path.unlink(missing_ok=True)
                window=window.settle(consumed=amount)
        return window

    def _owners(self):
        leases=self.db.execute('SELECT id,amount FROM byte_leases LIMIT 1025').fetchall()
        if len(leases)>MAX_LEASES or any(not isinstance(identity,str) or len(identity)!=32
                or any(c not in '0123456789abcdef' for c in identity)
                or type(amount) is not int or not 0<=amount<=16384 for identity,amount in leases):
            raise ValueError('invalid encrypted-byte owners')
        return leases

    def _save(self,window):
        self.db.execute('UPDATE bucket SET credits=?,observed=? WHERE id=1',(window.credits,window.observed))

    def _settle(self,wanted,*,refund=False):
        """Commit rights before use; leave pending writes inside outstanding."""
        with self._serialized():
            self._checkpoint()
            self.db.execute('BEGIN IMMEDIATE')
            created=None
            try:
                window=self._window(time.monotonic_ns())
                returned=self.remaining if refund else 0
                window=window.settle(consumed=self.spent,returned=returned)
                if self.credit_owner is None and wanted:
                    if self.db.execute('SELECT COUNT(*) FROM byte_leases').fetchone()[0]>=MAX_LEASES:
                        raise ValueError('encrypted-byte owner capacity exceeded')
                    identity=uuid.uuid4().hex
                    created=FileLock(self.path.parent/('credit-'+identity+'.mutex'))
                    if not created.acquire():raise ValueError('cannot own encrypted-byte rights')
                    self.db.execute('INSERT INTO byte_leases VALUES (?,0)',(identity,))
                else:
                    identity=self.credit_owner[0] if self.credit_owner else None
                grant=min(wanted,window.credits//1000000000)
                window=window.settle(granted=grant)
                if identity is not None:
                    old=self.db.execute('SELECT amount FROM byte_leases WHERE id=?',(identity,)).fetchone()
                    expected=self.remaining+self.pending+self.spent
                    if old is None or old[0]!=(0 if created else expected):
                        raise ValueError('encrypted-byte owner counters changed')
                    amount=(0 if created else old[0])-self.spent-returned+grant
                    self.db.execute('UPDATE byte_leases SET amount=? WHERE id=?',(amount,identity))
                self._save(window)
                self.db.commit()
                if created is not None:self.credit_owner=(identity,created)
                self.remaining=self.remaining-returned+grant
                self.spent=0
                return grant
            except BaseException:
                # A commit error can be ambiguous. Cached rights may already
                # have been returned; never reuse any after an uncertain write.
                self.credit_failed=True
                try:self.db.rollback()
                finally:
                    if created is not None:created.close()
                raise

    def chunks(self,data,stop):
        """Yield prepaid bounded slices; publish completion after each write.

        The generator must surround the actual write. A failed/abandoned write
        forfeits its full debit, and is never refunded as unused capacity.
        """
        position=0
        while position<len(data) and not stop.is_set():
            with self.lock:
                if self.closed or self.credit_failed:raise ValueError('encrypted-byte owner unavailable')
                if not self.remaining:
                    self._settle(min(self.chunk_size,max(2048,len(data)-position)))
                count=min(self.remaining,len(data)-position)
                if count:
                    self.remaining-=count
                    self.pending+=count
            if not count:
                stop.wait(min(0.05,max(0.001,1/self.rate)))
                continue
            try:
                yield data[position:position+count]
            finally:
                with self.lock:
                    # Even partial writes remain fully charged on failure.
                    self.pending-=count
                    self.spent+=count
            position+=count

    def idle(self):
        """Return never-issued rights so idle SSH sessions cannot hoard a burst."""
        with self.lock:
            if self.credit_failed:raise ValueError('encrypted-byte owner unavailable')
            if self.credit_owner and (self.remaining or self.spent):
                self._settle(0,refund=True)

    @contextmanager
    def _serialized(self):
        """Bound contention and serialize recovery, writes and checkpoints.

        Never unlink this inode: all processes must lock the same object.
        RLock handles the two relay directions inside one process; FileLock
        handles separate helpers and releases automatically on process death.
        """
        with self.lock:
            owner=FileLock(self.mutex)
            try:
                end=time.monotonic()+3
                while not owner.acquire():
                    if time.monotonic()>=end:
                        raise TimeoutError('encrypted-byte mutex unavailable')
                    time.sleep(0.001)
                yield
            finally:
                owner.close()

    def _checkpoint(self,*,force=False):
        """Keep the WAL bounded; a pinned reader stops further byte debits."""
        wal=Path(str(self.path)+'-wal')
        if wal.exists() and (force or wal.stat().st_size>=65536):
            busy,_,_=self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            if busy:
                raise ValueError('encrypted-byte checkpoint blocked')

    def take(self,count,stop):
        """Charge before passing bytes on; cancellation has no future debt."""
        while not stop.is_set():
            wait=self.reserve(count)
            if wait==0:
                return True
            stop.wait(min(wait,1.0))
        return False

    def close(self):
        with self.lock:
            if self.closed:return
            if self.pending:raise ValueError('encrypted-byte writes still pending')
            with self._serialized():
                removed=False
                try:
                    if self.credit_owner:
                        self.db.execute('BEGIN IMMEDIATE')
                        try:
                            window=self._window(time.monotonic_ns())
                            identity,_=self.credit_owner
                            row=self.db.execute('SELECT amount FROM byte_leases WHERE id=?',(identity,)).fetchone()
                            if row is None:raise ValueError('encrypted-byte owner vanished')
                            window=window.settle(consumed=row[0])
                            self.db.execute('DELETE FROM byte_leases WHERE id=?',(identity,))
                            self._save(window)
                            self.db.commit()
                            removed=True
                        except BaseException:
                            self.db.rollback()
                            raise
                finally:
                    try:self.db.close()
                    finally:
                        self.closed=True
                        if self.credit_owner:
                            _,owner=self.credit_owner
                            try:
                                owner.close()
                                if removed:owner.path.unlink(missing_ok=True)
                            finally:self.credit_owner=None
