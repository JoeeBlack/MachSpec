import frida
import logging
import time
import os
import sys

logger = logging.getLogger(__name__)

class DynamicProfiler:
    def __init__(self, target: str, is_spawn: bool = True):
        self.target = target
        self.is_spawn = is_spawn
        self.session = None
        self.script = None
    
    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            print(f"[*] {payload['type']}: {payload['function']}")
            print(f"    CONN: {payload['connection']}")
            print(f"    MSG:  {payload['message']}")
        else:
            print(message)

    def start(self):
        try:
            if self.is_spawn:
                print(f"[*] Spawning {self.target}...")
                pid = frida.spawn([self.target])
                self.session = frida.attach(pid)
            else:
                print(f"[*] Attaching to {self.target}...")
                self.session = frida.attach(self.target)

            # Load agent
            agent_path = os.path.join(os.path.dirname(__file__), '../../agents/tracer.js')
            agent_path = os.path.abspath(agent_path)
            
            with open(agent_path, 'r') as f:
                source = f.read()
            
            self.script = self.session.create_script(source)
            self.script.on('message', self.on_message)
            self.script.load()
            
            if self.is_spawn:
                frida.resume(pid)
                
            print("[*] Profiling started. Press Ctrl+C to stop.")
            sys.stdin.read()
            
        except frida.ProcessNotFoundError:
            logger.error(f"Process {self.target} not found.")
        except Exception as e:
            logger.error(f"Frida Error: {e}")
            if self.session:
                self.session.detach()
