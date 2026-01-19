import random
import string
import uuid
import base64
from typing import List, Dict, Any, Union

class XPCType:
    DICTIONARY = "dictionary"
    ARRAY = "array"
    INT64 = "int64"
    UINT64 = "uint64"
    STRING = "string"
    DATA = "data"
    UUID = "uuid"
    BOOL = "bool"
    FD = "fd"

class XPCMessageGenerator:
    """
    Generates random XPC messages for fuzzing purposes.
    """
    def __init__(self, dictionary_keys: List[str] = None):
        self.dictionary_keys = dictionary_keys or ["command", "action", "key", "value", "id"]

        self._primitive_generators = {
            XPCType.INT64: lambda: {"type": XPCType.INT64, "value": random.randint(-2**63, 2**63 - 1)},
            XPCType.UINT64: lambda: {"type": XPCType.UINT64, "value": random.randint(0, 2**64 - 1)},
            XPCType.STRING: lambda: {"type": XPCType.STRING, "value": ''.join(random.choices(string.ascii_letters, k=random.randint(1, 20)))},
            XPCType.BOOL: lambda: {"type": XPCType.BOOL, "value": random.choice([True, False])},
            XPCType.UUID: lambda: {"type": XPCType.UUID, "value": str(uuid.uuid4())},
            XPCType.DATA: lambda: {"type": XPCType.DATA, "value": base64.b64encode(random.randbytes(random.randint(1, 20))).decode('ascii')},
        }

    def generate_random_message(self, depth: int = 0, max_depth: int = 3) -> Dict[str, Any]:
        """
        Generates a random XPC message (Dictionary, Array, or Primitive).
        """
        if depth >= max_depth:
            return self.generate_primitive()
        
        # 50% chance of being a dictionary if at top level, otherwise mix
        r = random.random()
        if depth == 0 or r < 0.6:
            return self.generate_dictionary(depth + 1, max_depth)
        elif r < 0.9: # 30% chance (0.6 to 0.9)
            return self.generate_array(depth + 1, max_depth)
        else:
            return self.generate_primitive()

    def generate_dictionary(self, depth: int, max_depth: int) -> Dict[str, Any]:
        """Generates a random XPC dictionary."""
        msg = {"type": XPCType.DICTIONARY, "value": {}}
        # Ensure we don't try to pick more keys than available
        max_keys = min(len(self.dictionary_keys), 5)
        num_keys = random.randint(1, max_keys)

        # Sample keys without replacement to avoid overwriting
        keys = random.sample(self.dictionary_keys, num_keys)

        for key in keys:
            msg["value"][key] = self.generate_random_message(depth + 1, max_depth)
        return msg

    def generate_array(self, depth: int, max_depth: int) -> Dict[str, Any]:
        """Generates a random XPC array."""
        msg = {"type": XPCType.ARRAY, "value": []}
        num_items = random.randint(1, 5)
        for _ in range(num_items):
            msg["value"].append(self.generate_random_message(depth + 1, max_depth))
        return msg

    def generate_primitive(self) -> Dict[str, Any]:
        """Generates a random XPC primitive type."""
        t = random.choice(list(self._primitive_generators.keys()))
        return self._primitive_generators[t]()
