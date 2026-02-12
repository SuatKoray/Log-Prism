import json
import os
from datetime import datetime
from typing import List, Dict

class Reporter:
    """
    Module that saves analysis results with Geolocation features.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def save_report(self, alerts: List[Dict]) -> str:
        if not alerts: return None

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filepath = os.path.join(self.output_dir, f"security_report_{timestamp_str}.json")
        html_filepath = os.path.join(self.output_dir, f"security_report_{timestamp_str}.html")

        report_data = {
            "scan_date": datetime.now().isoformat(),
            "total_threats": len(alerts),
            "threats": alerts
        }

        try:
            with open(json_filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
        except IOError as e:
            print(f"[-] ERROR: Could not write JSON report -> {e}")

        self._generate_html(alerts, html_filepath, report_data["scan_date"])
        return html_filepath

    def _generate_html(self, alerts: List[Dict], filepath: str, scan_date: str):
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Log-Prism Intelligence Dashboard</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 0; padding: 30px; }}
                h1 {{ color: #58a6ff; text-align: center; border-bottom: 1px solid #30363d; padding-bottom: 15px; }}
                .summary {{ display: flex; justify-content: center; gap: 40px; background-color: #161b22; padding: 20px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #30363d; }}
                .summary-box {{ text-align: center; }}
                .summary-box h3 {{ margin: 0; color: #8b949e; font-size: 14px; text-transform: uppercase; }}
                .summary-box p {{ margin: 10px 0 0 0; font-size: 28px; font-weight: bold; color: #ffffff; }}
                table {{ width: 100%; border-collapse: collapse; background-color: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; }}
                th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #30363d; vertical-align: middle; }}
                th {{ background-color: #21262d; color: #58a6ff; font-weight: 600; text-transform: uppercase; font-size: 13px; }}
                tr:hover {{ background-color: #1c2128; }}
                .sev-CRITICAL {{ color: #ff7b72; font-weight: bold; }}
                .sev-HIGH {{ color: #ffa657; font-weight: bold; }}
                .sev-MEDIUM {{ color: #e3b341; font-weight: bold; }}
                .sev-LOW {{ color: #79c0ff; font-weight: bold; }}
                .flag {{ width: 20px; height: 15px; vertical-align: middle; margin-right: 8px; border-radius: 2px; }}
                .payload {{ font-family: 'Courier New', monospace; background-color: #000000; padding: 5px 8px; border-radius: 4px; color: #a5d6ff; font-size: 13px; }}
            </style>
        </head>
        <body>
            <h1>🛡️ Log-Prism Intelligence Dashboard</h1>
            <div class="summary">
                <div class="summary-box"><h3>Total Threats</h3><p>{len(alerts)}</p></div>
                <div class="summary-box"><h3>Scan Date</h3><p>{scan_date[:19].replace('T', ' ')}</p></div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Line</th>
                        <th>Location</th>
                        <th>Threat Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>Payload</th>
                    </tr>
                </thead>
                <tbody>
        """

        for alert in alerts:
            severity_class = f"sev-{alert['severity']}"
            line_num = alert.get('line_number', 'N/A')
            
            # Bayrak URL'si oluşturma
            country_code = alert.get('source_code', 'UNK').lower()
            if country_code in ['unk', 'loc', 'n/a']:
                flag_html = "🏳️" # Bilinmeyen veya yerel ağ için beyaz bayrak
            else:
                flag_html = f'<img src="https://flagcdn.com/24x18/{country_code}.png" class="flag" alt="{country_code}">'

            location_text = f"{flag_html} {alert.get('source_country', 'Unknown')}"

            html_content += f"""
                    <tr>
                        <td>{line_num}</td>
                        <td>{location_text}</td>
                        <td>{alert['alert_type']}</td>
                        <td class="{severity_class}">{alert['severity']}</td>
                        <td>{alert['description']}</td>
                        <td class="payload">{alert['payload']}</td>
                    </tr>
            """

        html_content += "</tbody></table></body></html>"

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
        except IOError as e:
            print(f"[-] ERROR: Could not write HTML report -> {e}")