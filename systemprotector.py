import subprocess

class SystemProtector:
    def __init__(self):
        self.blocked_ips = set()  # Store blocked IPs in a set

    def block_ip(self, ip):
        command_input = f"iptables -A INPUT -s {ip} -j DROP"  # Block incoming traffic from IP
        command_output = f"iptables -A OUTPUT -d {ip} -j DROP"  # Block outgoing traffic to IP
        try:
            subprocess.run(command_input, shell=True, check=True)  # Execute input blocking command
            subprocess.run(command_output, shell=True, check=True)  # Execute output blocking command
            self.blocked_ips.add(ip)  # Add IP to the blocked set
            print(f"Blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip}: {e}")  # Handle errors during blocking

    def unblock_ip(self, ip):
        command_input = f"iptables -D INPUT -s {ip} -j DROP"  # Unblock incoming traffic from IP
        command_output = f"iptables -D OUTPUT -d {ip} -j DROP"  # Unblock outgoing traffic to IP
        try:
            subprocess.run(command_input, shell=True, check=True)  # Execute input unblocking command
            subprocess.run(command_output, shell=True, check=True)  # Execute output unblocking command
            self.blocked_ips.discard(ip)  # Remove IP from the blocked set
            print(f"Unblocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to unblock IP {ip}: {e}")  # Handle errors during unblocking

    def list_blocked_ips(self):
        if self.blocked_ips:
            print(f"Blocked IPs: {', '.join(self.blocked_ips)}")  # List all blocked IPs
        else:
            print("No IPs are currently blocked.")  # Notify if no IPs are blocked