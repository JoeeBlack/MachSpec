import os
import plistlib
import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from ..database.models import Service
from .static_analyzer import StaticAnalyzer

logger = logging.getLogger(__name__)

class ServiceEnumerator:
    SYSTEM_PATHS = [
        "/System/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents"
    ]

    def __init__(self, db_session: Session):
        self.session = db_session

    def scan_system(self):
        """Scans standard system paths for LaunchAgents and Daemons."""
        for path in self.SYSTEM_PATHS:
            if not os.path.exists(path):
                continue
                
            logger.info(f"Scanning {path}...")
            self._scan_directory(path)

    def _scan_directory(self, directory: str):
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".plist"):
                    full_path = os.path.join(root, file)
                    self._process_plist(full_path)

    def _process_plist(self, plist_path: str):
        try:
            with open(plist_path, 'rb') as fp:
                try:
                    pl = plistlib.load(fp)
                except plistlib.InvalidFileException:
                    logger.warning(f"Invalid plist: {plist_path}")
                    return

            # Extract MachServices
            mach_services = pl.get("MachServices")
            if not mach_services:
                return

            # Can be a Dict or List, but usually Dict { "name": True/False }
            service_names = []
            if isinstance(mach_services, dict):
                service_names = list(mach_services.keys())
            elif isinstance(mach_services, list):
                # Rare but possible in some older contexts? Usually it's a dict for on-demand.
                # If it's just a list of strings
                service_names = mach_services
            
            # Extract Binary Path
            program = pl.get("Program")
            program_args = pl.get("ProgramArguments")
            
            binary_path = None
            if program:
                binary_path = program
            elif program_args and len(program_args) > 0:
                binary_path = program_args[0]
            
            # Resolve binary path if it is relative or implicitly in /usr/bin etc (rare for launchd but happens)
            # Actually launchd requires absolute paths usually, or relative to cwd which is / usually?
            # We'll trust what's there for now, or check existence.
            
            if binary_path and not binary_path.startswith("/"):
                # Heuristic: check standard paths if not absolute
                # But actually, often just the name is given if it's in path.
                # For now let's keep it as is.
                pass

            # Determine privileges based on directory
            is_root = False
            if "/System/Library/LaunchDaemons" in plist_path or "/Library/LaunchDaemons" in plist_path:
                is_root = True

            # Extract Metadata
            entitlements = None
            cs_reqs = None
            
            if binary_path and os.path.exists(binary_path):
                entitlements = StaticAnalyzer.get_entitlements(binary_path)
                cs_reqs = StaticAnalyzer.get_cs_reqs(binary_path)

            for svc_name in service_names:
                self._add_service_to_db(svc_name, binary_path, plist_path, is_root, entitlements, cs_reqs)

        except Exception as e:
            logger.error(f"Error processing {plist_path}: {e}")

    def _add_service_to_db(self, name, binary, plist, is_root, entitlements, cs_reqs):
        try:
            service = Service(
                name=name,
                binary_path=binary,
                plist_path=plist,
                is_root=is_root,
                entitlements=entitlements,
                codesign_requirements=cs_reqs,
                discovery_source="LaunchdPlist"
            )
            self.session.add(service)
            self.session.commit()
            logger.info(f"Added service: {name}")
        except IntegrityError:
            self.session.rollback()
            # Service already exists, maybe update? For now iterate.
            logger.debug(f"Service {name} already exists. Skipping.")
        except Exception as e:
            self.session.rollback()
            logger.error(f"DB Error adding {name}: {e}")
