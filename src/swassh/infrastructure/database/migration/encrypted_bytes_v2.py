"""Transactional Up/Down for byte rights; retain all committed token counters."""
APPLICATION_ID=0x53574257


class EncryptedByteSchema:
    """Only known schemas are adopted; downgrade requires no outstanding owners."""
    @staticmethod
    def up(db):
        version=db.execute('PRAGMA user_version').fetchone()[0]
        application=db.execute('PRAGMA application_id').fetchone()[0]
        if version==0 and application==0:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchone():
                raise ValueError('unknown encrypted-byte database schema')
            db.execute('CREATE TABLE bucket (id INTEGER PRIMARY KEY CHECK(id=1),rate INTEGER NOT NULL,credits INTEGER NOT NULL,observed INTEGER NOT NULL)')
            db.execute('PRAGMA application_id='+str(APPLICATION_ID))
        elif version not in (1,2) or application!=APPLICATION_ID:
            raise ValueError('unsupported encrypted-byte database version')
        expected={'bucket'} if version in (0,1) else {'bucket','byte_leases'}
        objects=db.execute("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if {name for name,kind in objects if kind=='table'}!=expected or any(kind!='table' for _,kind in objects):
            raise ValueError('invalid encrypted-byte database schema')
        if {row[1] for row in db.execute('PRAGMA table_info(bucket)')}!={'id','rate','credits','observed'}:
            raise ValueError('invalid encrypted-byte database schema')
        if version in (0,1):
            db.execute('CREATE TABLE byte_leases (id TEXT PRIMARY KEY NOT NULL,amount INTEGER NOT NULL CHECK(amount>=0 AND amount<=16384))')
            db.execute('PRAGMA user_version=2')
        if {row[1] for row in db.execute('PRAGMA table_info(byte_leases)')}!={'id','amount'}:
            raise ValueError('invalid encrypted-byte lease schema')

    @staticmethod
    def down(db):
        """Caller holds the byte mutex; stop invocations before rolling back."""
        EncryptedByteSchema.up(db)
        if db.execute('SELECT 1 FROM byte_leases LIMIT 1').fetchone():
            raise ValueError('cannot downgrade with encrypted-byte owners')
        db.execute('DROP TABLE byte_leases')
        db.execute('PRAGMA user_version=1')
