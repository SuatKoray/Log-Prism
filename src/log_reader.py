import os
from typing import Generator

class LogReader:
    """
    Memory-efficient log reader using Generator pattern.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

    def read_logs(self) -> Generator[str, None, None]:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"ERROR: File not found -> {self.file_path}")

        try:
            # Open with 'replace' to handle encoding errors gracefully
            with open(self.file_path, 'r', encoding='utf-8', errors='replace') as file:
                # [GÜNCELLENDİ] Artık İngilizce mesaj veriyor
                print(f"[*] Reading file: {self.file_path}")
                for line in file:
                    line = line.strip()
                    if line:
                        yield line
        except PermissionError:
            print(f"ERROR: Permission denied -> {self.file_path}")
        except Exception as e:
            print(f"UNEXPECTED ERROR: {str(e)}")