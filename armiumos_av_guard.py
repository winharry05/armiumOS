#!/usr/bin/env python3
import os
import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_DIR = "/root/Downloads"
QUARANTINE_DIR = "/root/Quarantine"

SUSPICIOUS_PATTERNS = [
    b"/bin/sh", b"/bin/bash",
    b"rm -rf", b"curl ", b"wget ",
    b"\xe7\xf0\x00\xf0",
]

class ArmiumOSScanner(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or event.src_path.endswith(".crdownload"):
            return
        
        filepath = event.src_path
        time.sleep(1)
        print(f"[armiumOS-AV] Imported file detected: {filepath}")
        
        if self.scan_file(filepath):
            self.quarantine(filepath)

    def scan_file(self, path):
        try:
            with open(path, "rb") as f:
                content = f.read()

            is_executable = content.startswith(b"\x7fELF")
            
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in content:
                    print(f"[armiumOS-AV ALERT] Threat pattern matched in {path}")
                    return True

            if is_executable:
                print(f"[armiumOS-AV] Executable imported. Enforcing 0644 safety mask.")
                os.chmod(path, 0o644)

        except Exception as e:
            print(f"[armiumOS-AV ERROR] Failed to scan file: {e}")
        return False

    def quarantine(self, path):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        filename = os.path.basename(path)
        dest = os.path.join(QUARANTINE_DIR, filename)
        os.rename(path, dest)
        print(f"[armiumOS-AV DANGER] File moved to Quarantine: {dest}")

if __name__ == "__main__":
    os.makedirs(WATCH_DIR, exist_ok=True)
    event_handler = ArmiumOSScanner()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()
    print("[armiumOS Security Engine] Active and watching imported files...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
