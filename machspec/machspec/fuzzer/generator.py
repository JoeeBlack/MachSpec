import random
import string
import uuid
import base64

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
    def __init__(self, dictionary_keys=None):
        self.dictionary_keys = dictionary_keys or ["command", "action", "key", "value", "id"]

    def generate_random_message(self, depth=0, max_depth=3):
        if depth >= max_depth:
            return self.generate_primitive()
        
        # 50% chance of being a dictionary if at top level, otherwise mix
        if depth == 0 or random.random() < 0.6:
            return self.generate_dictionary(depth + 1, max_depth)
        elif random.random() < 0.3:
            return self.generate_array(depth + 1, max_depth)
        else:
            return self.generate_primitive()

    def generate_dictionary(self, depth, max_depth):
        msg = {"type": XPCType.DICTIONARY, "value": {}}
        num_keys = random.randint(1, 5)
        for _ in range(num_keys):
            key = random.choice(self.dictionary_keys)
            msg["value"][key] = self.generate_random_message(depth + 1, max_depth)
        return msg

    def generate_array(self, depth, max_depth):
        msg = {"type": XPCType.ARRAY, "value": []}
        num_items = random.randint(1, 5)
        for _ in range(num_items):
            msg["value"].append(self.generate_random_message(depth + 1, max_depth))
        return msg

    def generate_primitive(self):
        t = random.choice([XPCType.INT64, XPCType.UINT64, XPCType.STRING, XPCType.BOOL, XPCType.UUID, XPCType.DATA])
        
        if t == XPCType.INT64:
            return {"type": t, "value": random.randint(-2**63, 2**63-1)}
        elif t == XPCType.UINT64:
            return {"type": t, "value": random.randint(0, 2**64-1)}
        elif t == XPCType.STRING:
            return {"type": t, "value": ''.join(random.choices(string.ascii_letters, k=random.randint(1, 20)))}
        elif t == XPCType.BOOL:
            return {"type": t, "value": random.choice([True, False])}
        elif t == XPCType.UUID:
            return {"type": t, "value": str(uuid.uuid4())}
        elif t == XPCType.DATA:
             # Random bytes base64 encoded
             b = random.randbytes(random.randint(1, 20))
             return {"type": t, "value": base64.b64encode(b).decode('ascii')}
        
        return {"type": XPCType.INT64, "value": 0}

