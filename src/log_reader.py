import os
from typing import Generator

class LogReader:


    def __init__(self, file_path: str):
        self.file_path = file_path

    def read_logs(self) -> Generator[str, None, None]:

        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"HATA: Dosya bulunamadı -> {self.file_path}")

        try:
            # 'utf-8' ile açıyoruz, okunamayan karakterleri 'replace' ile ? yapıyoruz ki çökmesin.
            with open(self.file_path, 'r', encoding='utf-8', errors='replace') as file:
                print(f"[*] Dosya okunuyor: {self.file_path}")
                for line in file:
                    line = line.strip()  # Satır başı/sonu boşluklarını temizle
                    if line:  # Boş satırları atla
                        yield line
        except PermissionError:
            print(f"HATA: Dosyayı okumak için yetkiniz yok -> {self.file_path}")
        except Exception as e:
            print(f"BEKLENMEDİK HATA: {str(e)}")