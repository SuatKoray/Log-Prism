import json
import re
import os
from typing import List, Dict, Optional
from collections import defaultdict

class Detector:
    """
    Log satırlarını tarayan ve davranışsal analiz yapan motor.
    """

    def __init__(self, signatures_path: str):
        self.signatures = self._load_signatures(signatures_path)
        self.compiled_rules = self._compile_rules()
        
        # [YENİ] IP adreslerinin kaç kez hata yaptığını tutan hafıza
        # Yapı: { "192.168.1.50": 5, "10.0.0.1": 1 }
        self.ip_tracker = defaultdict(int)
        self.BRUTE_FORCE_THRESHOLD = 5  # 5 hatadan sonrası saldırıdır

    def _load_signatures(self, path: str) -> List[Dict]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"İmza veritabanı bulunamadı: {path}")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            raise ValueError(f"HATA: JSON formatı bozuk -> {path}")

    def _compile_rules(self) -> List[Dict]:
        compiled = []
        for sig in self.signatures:
            try:
                sig['regex_obj'] = re.compile(sig['pattern'])
                compiled.append(sig)
            except re.error as e:
                print(f"UYARI: Regex hatası ID {sig.get('id')}: {e}")
        return compiled

    def scan_line(self, line: str) -> Optional[Dict]:
        """
        Hem imza tabanlı (Regex) hem de davranışsal (Brute Force) analiz yapar.
        """
        for rule in self.compiled_rules:
            match = rule['regex_obj'].search(line)
            if match:
                # Eğer SSH hatasıysa (Kategori ID'sine veya ismine bakabiliriz)
                if rule['category'] == "SSH Failure":
                    # Regex grubundan IP'yi çek (Pattern'de 2. grup IP idi)
                    # Pattern: ... user (group 1) from (group 2) ...
                    try:
                        attacker_ip = match.group(2)
                        self.ip_tracker[attacker_ip] += 1
                        
                        # Eşik değeri aşıldı mı?
                        if self.ip_tracker[attacker_ip] == self.BRUTE_FORCE_THRESHOLD:
                            return {
                                "original_log": line,
                                "alert_type": "BRUTE FORCE",
                                "severity": "CRITICAL",
                                "description": f"IP {attacker_ip} reached {self.BRUTE_FORCE_THRESHOLD} failed login attempts!",
                                "payload": attacker_ip
                            }
                        return None 
                    except IndexError:
                        pass # Regex grubu tutmazsa geç

                return {
                    "original_log": line,
                    "alert_type": rule['category'],
                    "severity": rule['severity'],
                    "description": rule['description'],
                    "payload": match.group(0)
                }
        return None