"""Initialize or remove an empty desired-state journal, in the caller transaction."""

APPLICATION_ID = 0x53574356


class ConvergenceSchema:
    """The journal never silently adopts or overwrites an unknown database."""

    @staticmethod
    def up(db):
        version = db.execute('PRAGMA user_version').fetchone()[0]
        application = db.execute('PRAGMA application_id').fetchone()[0]
        if version == 0 and application == 0:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1").fetchone():
                raise ValueError('desired-state database has an unknown schema')
            db.execute("CREATE TABLE records (id TEXT PRIMARY KEY NOT NULL, state TEXT NOT NULL CHECK(state IN ('checking','applying','verified','blocked')))")
            db.execute('CREATE TABLE capacity (id INTEGER PRIMARY KEY CHECK(id=1), records INTEGER NOT NULL CHECK(records>=0))')
            db.execute('INSERT INTO capacity VALUES (1,0)')
            db.execute('PRAGMA user_version=1')
            db.execute('PRAGMA application_id=' + str(APPLICATION_ID))
        elif version != 1 or application != APPLICATION_ID:
            raise ValueError('unsupported desired-state database version')
        if db.execute("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall() != [('capacity', 'table'), ('records', 'table')]:
            raise ValueError('unexpected desired-state schema objects')
        for table, expected in (('records', {'id', 'state'}), ('capacity', {'id', 'records'})):
            if {row[1] for row in db.execute('PRAGMA table_info(' + table + ')')} != expected:
                raise ValueError('invalid desired-state table schema')

    @staticmethod
    def down(db):
        """Refuse data loss; archive/reconcile a nonempty journal explicitly."""
        ConvergenceSchema.up(db)
        if db.execute('SELECT 1 FROM records LIMIT 1').fetchone():
            raise ValueError('cannot downgrade a nonempty desired-state journal; retain its evidence')
        db.execute('DROP TABLE records')
        db.execute('DROP TABLE capacity')
        db.execute('PRAGMA user_version=0')
        db.execute('PRAGMA application_id=0')
