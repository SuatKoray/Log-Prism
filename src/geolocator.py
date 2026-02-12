import requests
import json

class Geolocator:
    """
    Retrieves geolocation information for IP addresses using free APIs.
    Includes caching mechanism to avoid rate limits.
    """

    def __init__(self):
        self.api_url = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp"
        self.cache = {}

    def get_location(self, ip: str) -> dict:
        """
        Queries the API for the given IP address.
        Returns a dictionary with country and ISP info.
        """
        # 1. Check local cache first 
        if ip in self.cache:
            return self.cache[ip]

        # 2. Private IPs (Localhost, 192.168.x.x) don't have geolocation
        if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
            return {"country": "Local Network", "countryCode": "LOC", "isp": "Private"}

        # 3. Query the API
        try:
            response = requests.get(self.api_url.format(ip=ip), timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    result = {
                        "country": data.get("country", "Unknown"),
                        "countryCode": data.get("countryCode", "UNK"),
                        "isp": data.get("isp", "Unknown")
                    }
                    # Save to cache
                    self.cache[ip] = result
                    return result
        except Exception as e:
            print(f"[!] Geo-lookup failed for {ip}: {e}")

        return {"country": "Unknown", "countryCode": "UNK", "isp": "Unknown"}