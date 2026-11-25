"""The guardian's lightweight state must preserve the public model contracts."""
from dataclasses import asdict,fields,is_dataclass,replace,FrozenInstanceError
import pickle
import unittest

from swassh.domain.byte_credits import CreditPool
from swassh.domain.bandwidth import ByteWindow,NANOSECOND
from swassh.domain.credit_state import _CreditState
from swassh.infrastructure import bandwidth


class CreditRepresentationTests(unittest.TestCase):
    def test_public_dataclass_identity_fields_hash_replace_and_pickle_are_preserved(self):
        value=CreditPool(1024,1024*NANOSECOND,0)
        self.assertTrue(is_dataclass(value))
        self.assertEqual([field.name for field in fields(value)],['rate','credits','observed','outstanding'])
        self.assertEqual(asdict(value),dict(rate=1024,credits=1024*NANOSECOND,observed=0,outstanding=0))
        self.assertEqual(repr(value),'CreditPool(rate=1024, credits=1024000000000, observed=0, outstanding=0)')
        self.assertEqual(pickle.loads(pickle.dumps(value)),value)
        self.assertEqual(hash(value),hash(pickle.loads(pickle.dumps(value))))
        self.assertEqual(replace(value,observed=1).observed,1)
        self.assertIs(bandwidth.CreditPool,CreditPool);self.assertIs(bandwidth.ByteWindow,ByteWindow)
        with self.assertRaises(AttributeError):getattr(bandwidth,'not_a_model')
        with self.assertRaises(FrozenInstanceError):value.rate=2048
        with self.assertRaises(FrozenInstanceError):del value.rate

    def test_public_subclass_operations_keep_the_original_base_return_type(self):
        class Custom(CreditPool):pass
        value=Custom(1024,1024*NANOSECOND,0)
        self.assertIs(type(value.refill(1)),CreditPool)
        self.assertIs(type(value.settle(granted=1)),CreditPool)
        self.assertIs(type(value.debit(1)[0]),CreditPool)

    def test_internal_state_is_immutable_and_matches_each_public_transition(self):
        internal=_CreditState(1024,1024*NANOSECOND,0)
        public=CreditPool(1024,1024*NANOSECOND,0)
        for method,arguments in [('settle',{'granted':512}),('refill',{'now':NANOSECOND}),
                                 ('settle',{'consumed':100,'returned':412}),('refill',{'now':0})]:
            internal=getattr(internal,method)(**arguments);public=getattr(public,method)(**arguments)
            self.assertEqual(tuple(getattr(internal,name) for name in internal.__slots__),tuple(asdict(public).values()))
        with self.assertRaises(AttributeError):internal.rate=2048
        with self.assertRaises(AttributeError):del internal.rate
        self.assertIs(type(internal.debit(1)[0]),_CreditState)
        for values in ((True,0,0),(1024,True,0),(1024,0,True),(1024,0,0,True)):
            with self.assertRaises(ValueError):_CreditState(*values)
