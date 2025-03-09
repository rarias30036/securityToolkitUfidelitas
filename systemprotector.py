import subprocess

class SystemProtector:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip):
        # Block incoming traffic from the specified IP
        command_input = f"iptables -A INPUT -s {ip} -j DROP"
        # Block outgoing traffic to the specified IP 
        command_output = f"iptables -A OUTPUT -d {ip} -j DROP"
        try:
            # Execute the iptables commands to block the IP
            subprocess.run(command_input, shell=True, check=True)
            subprocess.run(command_output, shell=True, check=True)
            self.blocked_ips.add(ip)  # Add the IP to the set of blocked IPs
            print(f"\nIP {ip} blocked successfully.")
        except subprocess.CalledProcessError as e:
            print(f"\nFailed to block IP {ip}: {e}")

    def unblock_ip(self, ip):
        # Unblock incoming traffic from the specified IP
        command_input = f"iptables -D INPUT -s {ip} -j DROP"
        # Unblock outgoing traffic to the specified IP
        command_output = f"iptables -D OUTPUT -d {ip} -j DROP"
        try:
            # Execute the iptables commands to unblock the IP
            subprocess.run(command_input, shell=True, check=True)
            subprocess.run(command_output, shell=True, check=True)
            self.blocked_ips.discard(ip)  # Remove the IP from the set of blocked IPs
            print(f"\nIP {ip} unblocked successfully.")
        except subprocess.CalledProcessError as e:
            print(f"\nFailed to unblock IP {ip}: {e}")

    def list_blocked_ips(self):
        if self.blocked_ips:
            print("\nBlocked IPs:")
            for ip in self.blocked_ips:
                print(ip)
        else:
            print("\nNo IPs are currently blocked.")