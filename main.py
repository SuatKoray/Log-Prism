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
\033[1;36m
   __                  ___       _
  / /  ___   __ _     / _ \_ __ (_)___ _ __ ___
 / /  / _ \ / _` |___/ /_)/ '__|| / __| '_ ` _ \\
/ /__| (_) | (_| |__/ ___/| |   | \__ \ | | | | |
\____/\___/ \__, |  \/    |_|   |_|___/_| |_| |_|
            |___/
      🛡️  Intelligent Threat Detection & IPS v1.0
======================================================
\033[0m
"""

def parse_arguments():
    parser = argparse.ArgumentParser(description="Log-Prism: Python-Based Log Analysis Tool")
    parser.add_argument("-f", "--file", required=True, help="Path to the log file (e.g., logs/access.log)")
    parser.add_argument("-o", "--output", default="reports", help="Directory to save reports (Default: reports/)")
    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_arguments()

    if not os.path.exists(args.file):
        print(f"❌ [ERROR] Target file not found -> {args.file}")
        sys.exit(1)

    print(f"[*] Initializing analysis engine...")
    try:
        detector = Detector(SIGNATURES_FILE)
    except Exception as e:
        print(f"❌ [FATAL ERROR] Engine failed to start -> {e}")
        return

    reader = LogReader(args.file)
    reporter = Reporter(args.output)
    
    alerts = []
    start_time = time.time()

    print(f"[*] Scanning file: {args.file}\n" + "-"*54)
    
    try:
        for line_number, line in enumerate(reader.read_logs(), 1):
            alert = detector.scan_line(line)
            if alert:
                alert['line_number'] = line_number
                alerts.append(alert)
                print(f"   🚨 [LINE {line_number}] {alert['alert_type']} ({alert['severity']}) detected!")

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")

    duration = time.time() - start_time

    print("-" * 54)
    print(f"✅ Scan Completed in {duration:.2f} seconds.")
    print(f"📊 Total Threats Found: {len(alerts)}")

    if alerts:
        report_path = reporter.save_report(alerts)
        if report_path:
            print(f"📄 Dashboard generated: {report_path}")
    else:
        print("🎉 Clean log! No suspicious activity detected.")

if __name__ == "__main__":
    main()