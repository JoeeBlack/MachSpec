import subprocess
import plistlib
import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

class StaticAnalyzer:
    @staticmethod
    def get_entitlements(binary_path: str) -> Optional[Dict]:
        """Extract entitlements from a binary using codesign."""
        try:
            # -d: display, --entitlements -: output to stdout, --xml: xml format
            cmd = ["codesign", "-d", "--entitlements", "-", "--xml", binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Some binaries might not have entitlements or are not signed
                return None

            # codesign output often contains other info, valid plist is usually in the XML blob.
            # However, with --xml and - (stdout), it usually dumps just the plist.
            # But sometimes 'Executable=...' is printed to stderr.
            # Just parsing stdout should be fine.
            if not result.stdout.strip():
                return None
                
            data = result.stdout.encode('utf-8')
            try:
                entitlements = plistlib.loads(data)
                return entitlements
            except plistlib.InvalidFileException:
                # Sometimes it outputs non-xml blob header?
                # Let's try to find the xml part if pure parse failed
                start_xml = data.find(b'<?xml')
                if start_xml != -1:
                    clean_data = data[start_xml:]
                    return plistlib.loads(clean_data)
                return None

        except Exception as e:
            logger.error(f"Error extracting entitlements for {binary_path}: {e}")
            return None

    @staticmethod
    def get_cs_reqs(binary_path: str) -> Optional[str]:
        """Extract code signing requirements."""
        try:
            # -d: display, -r -: requirements to stdout
            cmd = ["codesign", "-d", "-r", "-", binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return None
                
            # Output format is usually "designated => ..."
            # We want the whole string.
            return result.stdout.strip()
            
        except Exception as e:
            logger.error(f"Error extracting cs_reqs for {binary_path}: {e}")
            return None

    @staticmethod
    def get_strings(binary_path: str, min_length: int = 4) -> list[str]:
        """Extract ASCII strings from binary."""
        try:
            cmd = ["strings", binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            if result.returncode != 0:
                return []
            
            # Simple filter and split
            all_strings = result.stdout.splitlines()
            return [s for s in all_strings if len(s) >= min_length]
        except Exception as e:
            logger.error(f"Error extracting strings for {binary_path}: {e}")
            return []

    @staticmethod
    def get_symbols(binary_path: str) -> list[str]:
        """Extract symbols using nm."""
        try:
            cmd = ["nm", "-g", binary_path] # -g for external symbols
            result = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            if result.returncode != 0:
                return []
            
            symbols = []
            for line in result.stdout.splitlines():
                if " U " in line: continue # Skip undefined
                parts = line.split()
                if len(parts) >= 3:
                     symbols.append(parts[2])
            return symbols
        except Exception as e:
            logger.error(f"Error extracting symbols for {binary_path}: {e}")
            return []

    @staticmethod
    def find_xpc_keys(strings: list[str]) -> list[str]:
        """Heuristically find potential XPC dictionary keys."""
        # This is a very basic heuristic.
        keys = []
        for s in strings:
            # Common patterns for keys:
            # - Reverse DNS style: com.company.something
            # - CamelCase starting with lowercase
            # - Underscore separated
            if "." in s and " " not in s and len(s) > 5:
                keys.append(s)
            elif "_" in s and " " not in s:
                keys.append(s)
        return keys
