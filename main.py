import argparse
import sys
import os
import time
import colorama
from colorama import Fore, Style


colorama.init(autoreset=True)

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.log_reader import LogReader
from src.detector import Detector
from src.reporter import Reporter

SIGNATURES_FILE = "config/signatures.json"


BANNER = fr"""{Fore.CYAN}{Style.BRIGHT}
   __                  ___       _
  / /  ___   __ _     / _ \_ __ (_)___ _ __ ___
 / /  / _ \ / _` |___/ /_)/ '__|| / __| '_ ` _ \
/ /__| (_) | (_| |__/ ___/| |   | \__ \ | | | | |
\____/\___/ \__, |  \/    |_|   |_|___/_| |_| |_|
            |___/
      🛡️  Intelligent Threat Detection & IPS v1.0
======================================================
{Style.RESET_ALL}"""

def parse_arguments():
    parser = argparse.ArgumentParser(description="Log-Prism: Python-Based Log Analysis Tool")
    
    parser.add_argument("-f", "--file", required=False, help="Path to the log file (e.g., logs/access.log)")
    parser.add_argument("-o", "--output", default="reports", help="Directory to save reports (Default: reports/)")
    parser.add_argument("-v", "--version", action="store_true", help="Show program version and exit")
    
    return parser.parse_args()

def main():
    print(BANNER)
    args = parse_arguments()

    # 1. KONTROL: Versiyon sorgusu
    if args.version:
        print(f"{Fore.GREEN}Log-Prism v1.0.0 (Stable) - 2026{Style.RESET_ALL}")
        sys.exit(0)

    # 2. KONTROL: Dosya verilmiş mi?
    if not args.file:
        print(f"{Fore.RED}❌ ERROR: You must specify a log file with -f or --file{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}   Usage: python main.py -f logs/auth.log{Style.RESET_ALL}")
        sys.exit(1)

    # 3. KONTROL: Dosya var mı?
    if not os.path.exists(args.file):
        print(f"{Fore.RED}❌ [ERROR] Target file not found -> {args.file}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"[*] Initializing analysis engine...")
    try:
        detector = Detector(SIGNATURES_FILE)
    except Exception as e:
        print(f"{Fore.RED}❌ [FATAL ERROR] Engine failed to start -> {e}{Style.RESET_ALL}")
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

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan aborted by user.{Style.RESET_ALL}")

    duration = time.time() - start_time

    print("-" * 54)
    print(f"{Fore.GREEN}✅ Scan Completed in {duration:.2f} seconds.{Style.RESET_ALL}")
    print(f"📊 Total Threats Found: {len(alerts)}")

    if alerts:
        report_path = reporter.save_report(alerts)
        if report_path:
            print(f"📄 Dashboard generated: {report_path}")
    else:
        print(f"{Fore.GREEN}🎉 Clean log! No suspicious activity detected.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()