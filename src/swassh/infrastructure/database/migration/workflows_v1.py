"""Transactional workflow schema; downgrade refuses persisted work or evidence."""

APPLICATION_ID = 0x5357464C


class WorkflowSchema:
    @staticmethod
    def up(db):
        version = db.execute('PRAGMA user_version').fetchone()[0]
        application = db.execute('PRAGMA application_id').fetchone()[0]
        if version == 0 and application == 0:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 1").fetchone():
                raise ValueError('workflow database has an unknown schema')
            db.execute("""CREATE TABLE runs (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN
                    ('pending','running','succeeded','failed','interrupted','cancelled')),
                created_at TEXT NOT NULL, payload TEXT NOT NULL CHECK(length(payload)<=10485760),
                payload_sha256 TEXT NOT NULL, checkpoint_sha256 TEXT NOT NULL)""")
            db.execute("""CREATE TABLE steps (
                run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                step_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
                needs TEXT NOT NULL CHECK(length(needs)<=32768),
                state TEXT NOT NULL CHECK(state IN
                    ('pending','running','succeeded','failed','blocked','interrupted','cancelled')),
                host_count INTEGER NOT NULL CHECK(host_count BETWEEN 1 AND 100000),
                report_path TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                reason TEXT, execution_id TEXT, counts TEXT, verification TEXT,
                reconciliation_count INTEGER NOT NULL DEFAULT 0 CHECK(reconciliation_count BETWEEN 0 AND 16),
                PRIMARY KEY(run_id,step_id), UNIQUE(run_id,ordinal))""")
            db.execute('CREATE INDEX workflow_runs_state ON runs(state,seq)')
            db.execute('CREATE INDEX workflow_steps_state ON steps(run_id,state,ordinal)')
            db.execute('CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL CHECK(length(payload)<=4096))')
            db.execute('PRAGMA application_id=' + str(APPLICATION_ID))
            db.execute('PRAGMA user_version=1')
        elif version != 1 or application != APPLICATION_ID:
            raise ValueError('unsupported workflow database version')
        expected = {'runs': {'seq','id','name','state','created_at','payload','payload_sha256','checkpoint_sha256'},
                    'steps': {'run_id','step_id','ordinal','needs','state','host_count','report_path',
                              'started_at','finished_at','reason','execution_id','counts','verification','reconciliation_count'},
                    'events': {'seq','payload'}}
        for table, columns in expected.items():
            if {row[1] for row in db.execute('PRAGMA table_info(' + table + ')')} != columns:
                raise ValueError('invalid workflow table schema')
        if db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
            raise ValueError('unexpected executable workflow schema objects')
        if db.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('invalid workflow references')

    @staticmethod
    def down(db):
        """Remove only an empty schema; retained audit outbox entries are data."""
        WorkflowSchema.up(db)
        for table in ('runs', 'steps', 'events'):
            if db.execute('SELECT 1 FROM ' + table + ' LIMIT 1').fetchone():
                raise ValueError('cannot downgrade a nonempty workflow store; retain work and audit evidence')
        for table in ('steps', 'runs', 'events'):
            db.execute('DROP TABLE ' + table)
        db.execute('PRAGMA user_version=0')
        db.execute('PRAGMA application_id=0')
