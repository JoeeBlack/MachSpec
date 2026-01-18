import random
import string
from .generator import XPCType

class XPCMutator:
    def __init__(self):
        pass

    def mutate(self, message):
        """Mutate a message structure in place or return new one."""
        # Simple recursion specific mutation
        if message["type"] == XPCType.DICTIONARY:
            self.mutate_dictionary(message)
        elif message["type"] == XPCType.ARRAY:
            self.mutate_array(message)
        else:
            self.mutate_primitive(message)
        return message

    def mutate_dictionary(self, message):
        # Action: Add key, Remove key, Mutate value, Change Key
        action = random.choice(["add", "remove", "mutate_value", "corrupt_key"])
        
        if action == "add":
            message["value"]["mutated_key"] = {"type": XPCType.STRING, "value": "A"*1000}
        elif action == "remove" and message["value"]:
            key = random.choice(list(message["value"].keys()))
            del message["value"][key]
        elif action == "mutate_value" and message["value"]:
            key = random.choice(list(message["value"].keys()))
            self.mutate(message["value"][key])
        elif action == "corrupt_key":
            # Can't easily change key in dict structure without re-assigning, skip for now
            pass

    def mutate_array(self, message):
        if not message["value"]:
            message["value"].append({"type": XPCType.INT64, "value": 0})
            return

        action = random.choice(["append", "remove", "mutate_element"])
        if action == "append":
            message["value"].append(message["value"][0]) # Duplicate first
        elif action == "remove":
            message["value"].pop()
        elif action == "mutate_element":
            self.mutate(random.choice(message["value"]))

    def mutate_primitive(self, message):
        t = message["type"]
        if t == XPCType.STRING:
            # Buffer overflow payload
            message["value"] = message["value"] * 100
        elif t in [XPCType.INT64, XPCType.UINT64]:
            message["value"] = random.choice([-1, 0, 2**63-1, 2**64-1])
        elif t == XPCType.BOOL:
            message["value"] = not message["value"]
