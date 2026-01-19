import random
import string
import copy
from typing import Dict, Any, List
from .generator import XPCType

class XPCMutator:
    """
    Mutates existing XPC messages to introduce faults or unexpected data.
    """
    def __init__(self):
        pass

    def mutate(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mutate a message structure in place or return a new one.

        Args:
            message: The XPC message dictionary (with 'type' and 'value').

        Returns:
            The mutated message dictionary.
        """
        # Simple recursion specific mutation
        if message["type"] == XPCType.DICTIONARY:
            self.mutate_dictionary(message)
        elif message["type"] == XPCType.ARRAY:
            self.mutate_array(message)
        else:
            self.mutate_primitive(message)
        return message

    def mutate_dictionary(self, message: Dict[str, Any]) -> None:
        """Mutates a dictionary type message."""
        # Action: Add key, Remove key, Mutate value, Change Key
        action = random.choice(["add", "remove", "mutate_value", "corrupt_key"])
        
        if action == "add":
            # Add a large payload to a new key
            message["value"]["mutated_key"] = {"type": XPCType.STRING, "value": "A" * 1000}
        elif action == "remove" and message["value"]:
            key = random.choice(list(message["value"].keys()))
            del message["value"][key]
        elif action == "mutate_value" and message["value"]:
            key = random.choice(list(message["value"].keys()))
            self.mutate(message["value"][key])
        elif action == "corrupt_key":
            # Can't easily change key in dict structure without re-assigning, skip for now
            pass

    def mutate_array(self, message: Dict[str, Any]) -> None:
        """Mutates an array type message."""
        if not message["value"]:
            message["value"].append({"type": XPCType.INT64, "value": 0})
            return

        action = random.choice(["append", "remove", "mutate_element"])
        if action == "append":
            if message["value"]:
                # Append a deep copy of a random element to ensure nested structures are independent
                message["value"].append(copy.deepcopy(random.choice(message["value"])))
            else:
                 message["value"].append({"type": XPCType.INT64, "value": 0})
        elif action == "remove":
            if message["value"]:
                message["value"].pop()
        elif action == "mutate_element":
            if message["value"]:
                self.mutate(random.choice(message["value"]))

    def mutate_primitive(self, message: Dict[str, Any]) -> None:
        """Mutates a primitive type message."""
        t = message["type"]
        if t == XPCType.STRING:
            # Buffer overflow payload, limited to avoid infinite explosion if called repeatedly in loop
            current_len = len(message["value"])
            if current_len < 100000:
                message["value"] = message["value"] * 100
            else:
                # If already huge, replace with format strings
                message["value"] = "%n" * 100
        elif t in [XPCType.INT64, XPCType.UINT64]:
            message["value"] = random.choice([-1, 0, 2**63-1, 2**64-1, -2**63])
        elif t == XPCType.BOOL:
            message["value"] = not message["value"]
