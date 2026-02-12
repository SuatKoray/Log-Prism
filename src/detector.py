import json
import re
import os
from typing import List, Dict, Optional
from collections import defaultdict
from src.geolocator import Geolocator  # [YENİ] Modülü ekledik

class Detector:
    """
    Threat detection engine with Regex, Behavioral Analysis, and Geolocation.
    """

    def __init__(self, signatures_path: str):
        self.signatures = self._load_signatures(signatures_path)
        self.compiled_rules = self._compile_rules()
        self.ip_tracker = defaultdict(int)
        self.BRUTE_FORCE_THRESHOLD = 5
        self.geo_engine = Geolocator() # [YENİ] Coğrafya motorunu başlat

    def _load_signatures(self, path: str) -> List[Dict]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Signature DB not found: {path}")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            raise ValueError(f"ERROR: Corrupt JSON format -> {path}")

    def _compile_rules(self) -> List[Dict]:
        compiled = []
        for sig in self.signatures:
            try:
                sig['regex_obj'] = re.compile(sig['pattern'])
                compiled.append(sig)
            except re.error as e:
                print(f"WARNING: Invalid Regex ID {sig.get('id')}: {e}")
        return compiled

    def _enrich_alert(self, alert_dict: dict, ip: str):
        """Adds geolocation data to the alert."""
        if ip:
            geo_info = self.geo_engine.get_location(ip)
            alert_dict['source_country'] = geo_info['country']
            alert_dict['source_code'] = geo_info['countryCode']
            alert_dict['isp'] = geo_info['isp']
        else:
            alert_dict['source_country'] = "N/A"
            alert_dict['source_code'] = "N/A"
            alert_dict['isp'] = "N/A"
        return alert_dict

    def scan_line(self, line: str) -> Optional[Dict]:
        for rule in self.compiled_rules:
            match = rule['regex_obj'].search(line)
            if match:
                # 1. SSH Brute Force Logic
                if rule['category'] == "SSH Failure":
                    try:
                        attacker_ip = match.group(2)
                        self.ip_tracker[attacker_ip] += 1
                        
                        if self.ip_tracker[attacker_ip] == self.BRUTE_FORCE_THRESHOLD:
                            alert = {
                                "original_log": line,
                                "alert_type": "SSH Brute Force",
                                "severity": "CRITICAL",
                                "description": f"IP {attacker_ip} reached {self.BRUTE_FORCE_THRESHOLD} failed attempts!",
                                "payload": attacker_ip
                            }
                            return self._enrich_alert(alert, attacker_ip) # [YENİ] Konum ekle
                        return None 
                    except IndexError:
                        pass

                # 2. Web Attack Logic (SQLi, XSS)
                # Try to extract IP from common log formats (usually the first part of the line)
                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                attacker_ip = ip_match.group(0) if ip_match else None

                alert = {
                    "original_log": line,
                    "alert_type": rule['category'],
                    "severity": rule['severity'],
                    "description": rule['description'],
                    "payload": match.group(0)
                }
                return self._enrich_alert(alert, attacker_ip) # [YENİ] Konum ekle
        return None