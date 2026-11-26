"""The version-aware stdlib rule preserves unconditional/external refusals."""
import ast
from pathlib import Path
import runpy
import unittest

policy=runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/import_policy.py'))['guarded_stdlib_import']


class FutureStdlibPolicyTests(unittest.TestCase):
    def accepted(self,source,module='annotationlib'):
        tree=ast.parse(source)
        parents={child:parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        node=next(item for item in ast.walk(tree) if isinstance(item,ast.Import) and item.names[0].name==module)
        return policy(module,node,tree,parents)

    def test_only_a_known_module_inside_a_sufficient_positive_version_guard_is_allowed(self):
        self.assertTrue(self.accepted('import sys\nif sys.version_info >= (3,14):\n    import annotationlib\n'))
        self.assertTrue(self.accepted('import sys\nif sys.version_info >= (3,15):\n    def inspect():\n        import annotationlib\n'))
        for source in ('import annotationlib\n',
                       'import sys\nif sys.version_info >= (3,13):\n    import annotationlib\n',
                       'import sys\nif sys.version_info <= (3,14):\n    import annotationlib\n',
                       'import sys\nif sys.version_info >= (3,14):\n    pass\nelse:\n    import annotationlib\n',
                       'if sys.version_info >= (3,14):\n    import annotationlib\n',
                       'import sys\nsys=object()\nif sys.version_info >= (3,14):\n    import annotationlib\n',
                       'import sys\nif sys.version_info >= (True,14):\n    import annotationlib\n'):
            with self.subTest(source=source):self.assertFalse(self.accepted(source))
        self.assertFalse(self.accepted('import sys\nif sys.version_info >= (3,14):\n    import unapproved_dependency\n',
                                       'unapproved_dependency'))
