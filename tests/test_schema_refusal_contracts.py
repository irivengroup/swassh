"""Isolated SQLite schema refusals and transactional Up/Down rollback proofs."""
import sqlite3
import unittest

from swassh.infrastructure.database.migration.convergence_v1 import ConvergenceSchema
from swassh.infrastructure.database.migration.encrypted_bytes_v2 import EncryptedByteSchema
from swassh.infrastructure.database.migration.workflows_v1 import WorkflowSchema


class SchemaRefusalIntegrationTests(unittest.TestCase):
    def database(self):
        db=sqlite3.connect(':memory:');self.addCleanup(db.close);return db

    def test_zero_version_with_a_foreign_application_marker_is_never_adopted(self):
        for schema in (ConvergenceSchema,EncryptedByteSchema,WorkflowSchema):
            db=self.database();db.execute('PRAGMA application_id=42')
            before=list(db.iterdump())
            with self.subTest(schema=schema.__name__),self.assertRaisesRegex(ValueError,'unsupported'):
                schema.up(db)
            self.assertEqual(list(db.iterdump()),before)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],0)
            self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0],42)

    def test_unknown_objects_versions_applications_and_columns_are_never_adopted(self):
        for schema in (ConvergenceSchema,EncryptedByteSchema,WorkflowSchema):
            for failure in ('unknown-object','version','application','column'):
                db=self.database()
                if failure=='unknown-object':db.execute('CREATE TABLE unrelated(value TEXT)')
                else:
                    schema.up(db)
                    if failure=='version':db.execute('PRAGMA user_version=99')
                    if failure=='application':db.execute('PRAGMA application_id=0')
                    if failure=='column':
                        table='records' if schema is ConvergenceSchema else 'bucket' if schema is EncryptedByteSchema else 'runs'
                        db.execute('ALTER TABLE '+table+' ADD COLUMN unexpected TEXT')
                before=list(db.iterdump())
                with self.subTest(schema=schema.__name__,failure=failure),self.assertRaises(ValueError):schema.up(db)
                self.assertEqual(list(db.iterdump()),before)

    def test_executable_schema_objects_and_invalid_foreign_references_are_refused(self):
        for schema in (ConvergenceSchema,EncryptedByteSchema,WorkflowSchema):
            for kind in ('view','trigger'):
                db=self.database();schema.up(db)
                if kind=='view':db.execute('CREATE VIEW unexpected AS SELECT 1 AS value')
                else:
                    table='records' if schema is ConvergenceSchema else 'bucket' if schema is EncryptedByteSchema else 'events'
                    db.execute('CREATE TRIGGER unexpected AFTER INSERT ON '+table+' BEGIN SELECT 1; END')
                with self.subTest(schema=schema.__name__,kind=kind),self.assertRaises(ValueError):schema.up(db)
        db=self.database();WorkflowSchema.up(db)
        # Model an imported damaged database. The production store enables FK
        # enforcement; the migration must also detect pre-existing violations.
        db.execute("INSERT INTO steps(run_id,step_id,ordinal,needs,state,host_count,report_path) VALUES ('missing','one',0,'[]','pending',1,'synthetic')")
        with self.assertRaisesRegex(ValueError,'references'):WorkflowSchema.up(db)

    def test_partial_up_failures_roll_back_every_table_and_version_marker(self):
        for schema,statement in ((ConvergenceSchema,'CREATE TABLE capacity'),
                (EncryptedByteSchema,'CREATE TABLE byte_leases'),(WorkflowSchema,'CREATE INDEX workflow_steps_state')):
            db=self.database()
            class FaultPort:
                def execute(self,sql,*args):
                    if sql.startswith(statement):raise sqlite3.OperationalError('synthetic migration fault')
                    return db.execute(sql,*args)
            db.execute('BEGIN')
            with self.assertRaisesRegex(sqlite3.OperationalError,'migration fault'):schema.up(FaultPort())
            db.rollback()
            self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall(),[])
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],0)
            self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0],0)

    def test_byte_down_rollback_preserves_tokens_when_version_write_fails_after_drop(self):
        db=self.database();EncryptedByteSchema.up(db)
        db.execute('INSERT INTO bucket VALUES (1,1024,100000000,7)');db.commit()
        class FaultPort:
            def execute(self,sql,*args):
                if sql=='PRAGMA user_version=1':raise sqlite3.OperationalError('synthetic downgrade fault')
                return db.execute(sql,*args)
        db.execute('BEGIN')
        with self.assertRaisesRegex(sqlite3.OperationalError,'downgrade fault'):EncryptedByteSchema.down(FaultPort())
        db.rollback()
        self.assertEqual(db.execute('SELECT rate,credits,observed FROM bucket').fetchall(),[(1024,100000000,7)])
        self.assertEqual(db.execute('SELECT * FROM byte_leases').fetchall(),[])
        self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],2)
        db.execute('ALTER TABLE byte_leases ADD COLUMN unexpected TEXT')
        with self.assertRaisesRegex(ValueError,'lease schema'):EncryptedByteSchema.up(db)


if __name__=='__main__':unittest.main()
