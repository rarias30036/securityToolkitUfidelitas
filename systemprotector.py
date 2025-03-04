import subprocess

class SystemProtector:
    def __init__(self):
        pass

    def block_ip(self, ip):
        # Create an iptables command to block the specified IP
        command = f"iptables -A INPUT -s {ip} -j DROP"
        try:
            # Execute the iptables command using subprocess
            subprocess.run(command, shell=True, check=True)
            print(f"\nIP {ip} blocked successfully.")
        except subprocess.CalledProcessError as e:
            print(f"\nFailed to block IP {ip}: {e}")