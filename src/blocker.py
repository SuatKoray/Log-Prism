import subprocess
import sys
import os

class FirewallBlocker:
    """
    Manages Windows Firewall rules to block malicious IP addresses.
    """
    
    def __init__(self):
        # Prevent self-lockout (Whitelist)
        self.whitelist = ["127.0.0.1", "localhost", "192.168.1.1"]
        
    def block_ip(self, ip: str):
        """
        Adds an inbound block rule to Windows Firewall for the specified IP.
        """
        if ip in self.whitelist or ip.startswith("192.168."):
            print(f"[!] SECURITY: {ip} is in whitelist. Action skipped.")
            return False

        rule_name = f"LogPrism_Block_{ip}"
        
        # Windows Firewall Command (netsh)
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'

        try:
            print(f"[*] BLOCKING: Adding firewall rule for {ip}...")
            
            # Execute command
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if "Ok." in result.stdout or "Tamam." in result.stdout:
                print(f"✅ SUCCESS: {ip} successfully blocked by Windows Firewall.")
                return True
            else:
                if "Run as administrator" in result.stdout or "Yönetici olarak" in result.stdout:
                    print(f"❌ ERROR: You must run the terminal as ADMINISTRATOR to block IPs!")
                else:
                    print(f"❌ ERROR: {result.stdout.strip()} {result.stderr.strip()}")
                return False
                
        except Exception as e:
            print(f"❌ UNEXPECTED ERROR: {e}")
            return False