"""Recognize a known future stdlib module only in a verified version branch.

Python 3.14 adds annotationlib. Older CI runtimes inspect the same test sources;
an unconditional import still fails, as does every unknown external module.
"""
import ast

INTRODUCED={'annotationlib':(3,14)}


def guarded_stdlib_import(module,node,tree,parents):
    """Accept only the positive arm of a literal canonical sys version guard."""
    required=INTRODUCED.get(module)
    if required is None:return False
    imported=any(isinstance(item,ast.Import) and any(alias.name=='sys' and alias.asname in (None,'sys')
                                                   for alias in item.names) for item in tree.body)
    rebound=any(isinstance(item,ast.Name) and isinstance(item.ctx,ast.Store) and item.id=='sys'
                or isinstance(item,ast.arg) and item.arg=='sys'
                or isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and item.name=='sys'
                for item in ast.walk(tree))
    if not imported or rebound:return False
    child=node
    while child in parents:
        parent=parents[child]
        if isinstance(parent,ast.If) and child in parent.body:
            test=parent.test
            if (isinstance(test,ast.Compare) and len(test.ops)==1 and isinstance(test.ops[0],ast.GtE)
                    and isinstance(test.left,ast.Attribute) and test.left.attr=='version_info'
                    and isinstance(test.left.value,ast.Name) and test.left.value.id=='sys'
                    and len(test.comparators)==1 and isinstance(test.comparators[0],ast.Tuple)):
                values=test.comparators[0].elts
                if (len(values)==2 and all(isinstance(value,ast.Constant) and type(value.value) is int for value in values)
                        and tuple(value.value for value in values)>=required):
                    return True
        child=parent
    return False
