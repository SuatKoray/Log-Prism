import os
import time

class LogReader:
    """
    Reads log files statically or tracks them in real-time (Live Tailing).
    """
    def __init__(self, file_path: str):
        self.file_path = file_path

    def read_logs(self, live: bool = False):
        """
        Yields log lines. If live=True, it waits for new lines indefinitely.
        """
        with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
            if not live:
                # Normal Okuma: Baştan sona oku ve bitir
                for line in f:
                    yield line.strip()
            else:
                # Canlı İzleme : Dosyanın sonuna git ve bekle
                f.seek(0, os.SEEK_END)
                print("\n👀 LIVE MODE ACTIVE: Waiting for new logs... (Press Ctrl+C to stop)")
                
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)  # Yeni satır yoksa yarım saniye uyu, sistemi yorma
                        continue
                    yield line.strip()