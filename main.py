import argparse
import sys
import os
import time


sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.log_reader import LogReader
from src.detector import Detector
from src.reporter import Reporter


SIGNATURES_FILE = "config/signatures.json"
BANNER = """
==================================================
   🛡️  LOG-PRISM | Log Analysis & Threat Tool
==================================================
"""

def parse_arguments():

    parser = argparse.ArgumentParser(description="Log-Prism: Python Tabanlı Log Analiz Aracı")
    
    parser.add_argument(
        "-f", "--file", 
        required=True, 
        help="Analiz edilecek log dosyasının yolu (Örn: logs/access.log)"
    )
    
    parser.add_argument(
        "-o", "--output", 
        default="reports", 
        help="Raporların kaydedileceği klasör (Varsayılan: reports/)"
    )

    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_arguments()

    # 1. Başlangıç 
    if not os.path.exists(args.file):
        print(f"❌ HATA: Belirtilen dosya bulunamadı -> {args.file}")
        sys.exit(1)

    # 2. Modüller
    print(f"[*] Motor başlatılıyor...")
    detector = Detector(SIGNATURES_FILE)
    reader = LogReader(args.file)
    reporter = Reporter(args.output)
    
    alerts = []
    start_time = time.time()

    # 3. Analiz Döngüsü
    print(f"[*] Analiz yapılıyor: {args.file}")
    
    try:
        for line_number, line in enumerate(reader.read_logs(), 1):
            alert = detector.scan_line(line)
            if alert:
                # Satır numarasını da ekleyelim
                alert['line_number'] = line_number
                alerts.append(alert)
                # Konsola anlık bildirim (Opsiyonel)
                print(f"   🚨 [SATIR {line_number}] {alert['alert_type']} tespit edildi!")

    except KeyboardInterrupt:
        print("\n[!] Analiz kullanıcı tarafından durduruldu.")

    duration = time.time() - start_time

    # 4. Raporlama
    print("-" * 50)
    print(f"✅ Analiz Tamamlandı ({duration:.2f} saniye)")
    print(f"📊 Toplam Tehdit Sayısı: {len(alerts)}")

    if alerts:
        report_path = reporter.save_report(alerts)
        if report_path:
            print(f"📄 Rapor kaydedildi: {report_path}")
    else:
        print("🎉 Log dosyasında şüpheli bir aktivite bulunamadı!")

if __name__ == "__main__":
    main()