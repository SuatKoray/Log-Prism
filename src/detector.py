import json
import re
import os
from typing import List, Dict, Optional

class Detector:

    def __init__(self, signatures_path: str):

        self.signatures = self._load_signatures(signatures_path)
        self.compiled_rules = self._compile_rules()


    def _load_signatures(self, path: str) -> List[Dict]:
        """JSON dosyasından imzaları okur."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"İmza veritabanı bulunamadı: {path}")
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            raise ValueError(f"HATA: {path} dosyası bozuk veya geçersiz JSON formatında.")


    def _compile_rules(self) -> List[Dict]:
        compiled = []
        for sig in self.signatures:
            try:
                # Regex'i derle ve sözlüğe ekle
                sig['regex_obj'] = re.compile(sig['pattern'])
                compiled.append(sig)
            except re.error as e:
                print(f"UYARI: Geçersiz Regex atlandı ID {sig.get('id')}: {e}")
        
        print(f"[*] {len(compiled)} adet saldırı imzası yüklendi ve derlendi.")
        return compiled



    def scan_line(self, line: str) -> Optional[Dict]:
        for rule in self.compiled_rules:
            match = rule['regex_obj'].search(line)
            if match:
                return {
                    "original_log": line,
                    "alert_type": rule['category'],
                    "severity": rule['severity'],
                    "description": rule['description'],
                    "payload": match.group(0) # Yakalanan zararlı kısım
                }
        return None