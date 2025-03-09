import nmap
import subprocess

class PortScanner:
    def __init__(self):
        self.scan_results = ""

    def autoScan(self, target):
        # Check if the target is empty
        if not target.strip():
            print("Invalid target. Please enter a valid IP or hostname.")
            return

        # Create an instance of the nmap.PortScanner class
        nmap_scanner = nmap.PortScanner()
        try:
            print(f"\nScanning target: {target}...")
            # Scan all ports on the target using the TCP connect scan method
            nmap_scanner.scan(target, arguments="-p- -sT")
            # Format the scan results and print them
            self.scan_results = self._format_scan_results(nmap_scanner)
            print(self.scan_results)
        except Exception as e:
            print(f"Error during scanning: {e}")

    def scan_with_nmap(self, command):
        # Check if the command starts with nmap
        if not command.strip().startswith("nmap"):
            print("Invalid command. Please enter a valid Nmap command.")
            return

        try:
            print(f"\nExecuting custom Nmap command: {command}")
            # Execute the custom Nmap command using subprocess
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            print(result.stdout)
            self.scan_results = result.stdout
        except Exception as e:
            print(f"Error executing Nmap: {e}")

    def _format_scan_results(self, nmap_scanner):
        result = "********************** Scan Report **********************\n"
        # Loop through all hosts in the scan results and add host info to scan results
        for host in nmap_scanner.all_hosts():
            result += f"\nHost: {host} | State: {nmap_scanner[host].state()}\n"
            # Loop through all protocols like tcp or udp for the host
            for protocol in nmap_scanner[host].all_protocols():
                result += f"\nProtocol: {protocol}\n"
                result += "Port\t\tState\t\tService\n"
                # Loop through all ports for the protocol
                for port in nmap_scanner[host][protocol].keys():
                    # Get the service name and state for the port
                    name = nmap_scanner[host][protocol][port]['name']
                    state = nmap_scanner[host][protocol][port]['state']
                    # Add port information to the result string
                    result += f"{port}\t\t{state}\t\t{name}\n"
        # Return the formatted scan results
        return result