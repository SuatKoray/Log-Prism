import json
import os
from datetime import datetime
from typing import List, Dict

class Reporter:

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        # Rapor klasörü yoksa oluştur (Garanti olsun)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def save_report(self, alerts: List[Dict]) -> str:
  
        if not alerts:
            print("[-] Kaydedilecek tehdit bulunamadı.")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        report_data = {
            "scan_date": datetime.now().isoformat(),
            "total_threats": len(alerts),
            "threats": alerts
        }

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            return filepath
        except IOError as e:
            print(f"HATA: Rapor dosyası yazılamadı -> {e}")
            return None