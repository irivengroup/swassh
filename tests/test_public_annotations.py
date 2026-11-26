"""SDK type metadata is consumable by typing tools and documentation builders.

Only SWASSH's own trusted definitions are introspected. No Protocol method body
or application command is called to exercise annotations.
"""
import inspect
import importlib
from pathlib import Path
import sys
import typing
import unittest

import swassh

if sys.version_info >= (3,14):
    import annotationlib


def public_definitions():
    """Yield public exports plus their declared methods without descriptors."""
    seen=set()
    for name in swassh.__all__:
        owner=getattr(swassh,name)
        if not (inspect.isclass(owner) or inspect.isfunction(owner)):
            continue
        candidates=[(name,owner)]
        if inspect.isclass(owner):
            for attribute,value in vars(owner).items():
                if isinstance(value,(classmethod,staticmethod)):
                    value=value.__func__
                if isinstance(value,property):
                    value=value.fget
                if inspect.isfunction(value):
                    candidates.append((name+'.'+attribute,value))
        for label,value in candidates:
            if id(value) not in seen:
                seen.add(id(value))
                yield label,value


class PublicAnnotationContracts(unittest.TestCase):
    def test_public_type_hints_resolve_without_invoking_runtime_operations(self):
        count=0
        for name,owner in public_definitions():
            with self.subTest(definition=name):
                hints=typing.get_type_hints(owner)
                self.assertIsInstance(hints,dict)
                self.assertTrue(all(isinstance(key,str) for key in hints))
                count+=bool(hints)
        self.assertGreater(count,50)
        self.assertEqual(typing.get_type_hints(swassh.Host)['hostname'],str)
        self.assertEqual(typing.get_type_hints(swassh.DesiredState)['check'],str)

    @unittest.skipUnless(sys.version_info>=(3,14),'annotation formats require Python 3.14')
    def test_runtime_and_documentation_formats_are_consistent_on_python_314(self):
        count=0
        for name,owner in public_definitions():
            annotate=getattr(owner,'__annotate__',None)
            if annotate is None:
                continue
            with self.subTest(definition=name):
                values=annotationlib.call_annotate_function(annotate,annotationlib.Format.VALUE,owner=owner)
                forward=annotationlib.call_annotate_function(annotate,annotationlib.Format.FORWARDREF,owner=owner)
                strings=annotationlib.call_annotate_function(annotate,annotationlib.Format.STRING,owner=owner)
                self.assertEqual(set(values),set(forward))
                self.assertEqual(set(values),set(strings))
                self.assertTrue(all(isinstance(text,str) for text in strings.values()))
                count+=1
        self.assertGreater(count,50)

    @unittest.skipUnless(sys.version_info>=(3,14),'annotation formats require Python 3.14')
    def test_source_documentation_can_read_internal_contract_signatures_as_forward_references(self):
        root=Path(__file__).resolve().parents[1]/'src/swassh'
        seen=set();checked=0
        for path in sorted(root.rglob('*.py')):
            if path.name=='__main__.py':continue  # This module is a CLI entry point.
            parts=path.relative_to(root.parent).with_suffix('').parts
            if parts[-1]=='__init__':parts=parts[:-1]
            module=importlib.import_module('.'.join(parts))
            owners=[module]
            for owner in tuple(vars(module).values()):
                if (inspect.isfunction(owner) or inspect.isclass(owner)) and getattr(owner,'__module__','').startswith('swassh'):
                    owners.append(owner)
                    if inspect.isclass(owner):
                        for value in vars(owner).values():
                            if isinstance(value,(classmethod,staticmethod)):value=value.__func__
                            if isinstance(value,property):value=value.fget
                            if inspect.isfunction(value):owners.append(value)
            for owner in owners:
                annotate=getattr(owner,'__annotate__',None)
                if annotate is None or id(annotate) in seen:continue
                seen.add(id(annotate))
                with self.subTest(module=module.__name__,owner=getattr(owner,'__qualname__','module')):
                    forward=annotationlib.call_annotate_function(annotate,annotationlib.Format.FORWARDREF,owner=owner)
                    strings=annotationlib.call_annotate_function(annotate,annotationlib.Format.STRING,owner=owner)
                    self.assertEqual(set(forward),set(strings))
                    self.assertTrue(all(isinstance(value,str) for value in strings.values()))
                    checked+=1
        self.assertGreater(checked,100)
