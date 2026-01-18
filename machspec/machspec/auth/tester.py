import logging
import subprocess
import json
import os
import time

logger = logging.getLogger(__name__)

class AuthTester:
    def __init__(self, service_name, binary_path=None):
        self.service_name = service_name
        
        if binary_path:
            self.client_bin = binary_path
        else:
             base = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
             self.client_bin = os.path.join(base, "native/XPCClient/.build/release/XPCClient")

    def test_connection_validity(self):
        """Test if we can connect and keep connection open without proper entitlements."""
        logger.info(f"Testing auth for {self.service_name}...")
        
        # Send a benign message
        msg = {"type": "dictionary", "value": { "command": {"type": "string", "value": "status"} }}
        payload = json.dumps(msg)
        
        try:
            proc = subprocess.Popen(
                [self.client_bin, self.service_name],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(input=payload.encode('utf-8'), timeout=5)
            
            output = stdout.decode()
            err_output = stderr.decode()
            
            result = {
                "service": self.service_name,
                "connection_allowed": True,
                "reply_received": False,
                "error": None
            }
            
            if "XPC Error: Connection invalid" in output or "Connection invalid" in output:
                result["connection_allowed"] = False
                result["error"] = "Connection Invalid (Likely Entitlement Check Failed)"
            elif "XPC Error: Connection interrupted" in output:
                 result["connection_allowed"] = False
                 result["error"] = "Connection Interrupted"
            elif output.strip():
                result["reply_received"] = True
                result["reply"] = output.strip()
            
            return result
            
        except subprocess.TimeoutExpired:
            proc.kill()
            return {"service": self.service_name, "connection_allowed": True, "timeout": True}
        except Exception as e:
            return {"service": self.service_name, "error": str(e)}
