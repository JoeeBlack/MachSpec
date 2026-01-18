import subprocess
import json
import logging
import os
import signal
from datetime import datetime
from .generator import XPCMessageGenerator
from .mutator import XPCMutator

logger = logging.getLogger(__name__)

class FuzzEngine:
    def __init__(self, service_name, binary_path=None):
        self.service_name = service_name
        self.generator = XPCMessageGenerator()
        self.mutator = XPCMutator()
        
        if binary_path:
            self.client_bin = binary_path
        else:
             # Try to find it relative to this file
             # machspec/machspec/fuzzer/engine.py -> machspec/native/XPCClient/.build/release/XPCClient
             base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
             self.client_bin = os.path.join(base, "machspec/native/XPCClient/.build/release/XPCClient")

    def fuzz(self, iterations=100):
        if not os.path.exists(self.client_bin):
            logger.error(f"XPCClient binary not found at {self.client_bin}")
            return

        logger.info(f"Starting Fuzzing on {self.service_name} for {iterations} iterations...")
        
        crashes = 0
        for i in range(iterations):
            # Generate
            msg = self.generator.generate_random_message()
            # Mutate
            msg = self.mutator.mutate(msg)
            
            payload = json.dumps(msg)
            
            try:
                # Run Client
                # We pipe input
                proc = subprocess.Popen(
                    [self.client_bin, self.service_name],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                stdout, stderr = proc.communicate(input=payload.encode('utf-8'), timeout=2)
                
                if proc.returncode != 0:
                    # Check for crash signals (negatives)
                    # Python subproces returncode is -signal
                    if proc.returncode < 0:
                        sig = -proc.returncode
                        if sig in [signal.SIGSEGV, signal.SIGBUS, signal.SIGILL, signal.SIGABRT]:
                            crashes += 1
                            self._save_crash(msg, stderr, sig)
                            logger.critical(f"CRASH detected! Signal {sig}")
                        else:
                            # Other signals
                            pass
                    else:
                        # Non-zero exit (error reported by client)
                        # logger.debug(f"Client error: {stderr.decode()}")
                        pass
                else:
                    # Success
                    # logger.debug(f"Reply: {stdout.decode()}")
                    pass
                    
            except subprocess.TimeoutExpired:
                proc.kill()
                logger.warning("Timeout")
            except Exception as e:
                logger.error(f"Execution error: {e}")
                
            if i % 10 == 0:
                print(f"Iter {i}/{iterations} | Crashes: {crashes}", end='\r')
        
        print(f"\nFuzzing finished. Total crashes: {crashes}")

    def _save_crash(self, message, log, signal):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"crash_{self.service_name}_{timestamp}_sig{signal}.json"
        with open(filename, 'w') as f:
            json.dump({
                "service": self.service_name,
                "signal": signal,
                "log": log.decode('utf-8', errors='ignore'),
                "payload": message
            }, f, indent=2)
        logger.info(f"Saved crash artifact to {filename}")
