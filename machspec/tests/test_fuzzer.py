import unittest
from machspec.machspec.fuzzer.generator import XPCMessageGenerator, XPCType
from machspec.machspec.fuzzer.mutator import XPCMutator

class TestXPCGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = XPCMessageGenerator()

    def test_generate_primitive(self):
        msg = self.generator.generate_primitive()
        self.assertIn("type", msg)
        self.assertIn("value", msg)
        self.assertIn(msg["type"], [XPCType.INT64, XPCType.UINT64, XPCType.STRING, XPCType.BOOL, XPCType.UUID, XPCType.DATA])

    def test_generate_dictionary(self):
        msg = self.generator.generate_dictionary(0, 2)
        self.assertEqual(msg["type"], XPCType.DICTIONARY)
        self.assertIsInstance(msg["value"], dict)
        self.assertGreaterEqual(len(msg["value"]), 1)

    def test_generate_array(self):
        msg = self.generator.generate_array(0, 2)
        self.assertEqual(msg["type"], XPCType.ARRAY)
        self.assertIsInstance(msg["value"], list)

class TestXPCMutator(unittest.TestCase):
    def setUp(self):
        self.mutator = XPCMutator()

    def test_mutate_primitive_string(self):
        msg = {"type": XPCType.STRING, "value": "test"}
        self.mutator.mutate_primitive(msg)
        # Expect overflow payload or changed string
        self.assertNotEqual(msg["value"], "test")
        self.assertTrue(len(msg["value"]) > 4)

    def test_mutate_primitive_int(self):
        msg = {"type": XPCType.INT64, "value": 100}
        self.mutator.mutate_primitive(msg)
        self.assertIn(msg["value"], [-1, 0, 2**63-1, 2**64-1, -2**63])

if __name__ == '__main__':
    unittest.main()
