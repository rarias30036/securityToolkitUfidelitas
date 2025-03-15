import nmap
import subprocess

class PortScanner:
    def __init__(self):
        self.scan_results = ""  # Store the results of the port scan

    def autoScan(self, target):
        """Perform an automatic scan of all ports on the specified target."""
        if not target.strip():  # Check if the target is empty
            print("Invalid target. Please enter a valid IP or hostname.")
            return

        nmap_scanner = nmap.PortScanner()  # Create an Nmap scanner object
        try:
            print(f"Scanning target: {target}...")
            # Scan all ports (-p-) using TCP connections (-sT)
            nmap_scanner.scan(target, arguments="-p- -sT")
            self.scan_results = self._format_scan_results(nmap_scanner)  # Format the results
            print(self.scan_results)  # Display the results in the console
        except Exception as e:
            print(f"Error during scanning: {e}")  # Handle errors during scanning

    def scan_with_nmap(self, command):
        """Execute a custom Nmap command."""
        if not command.strip().startswith("nmap"):  # Check if the command starts with "nmap"
            print("Invalid command. Please enter a valid Nmap command.")
            return

        try:
            print(f"Executing custom Nmap command: {command}")
            # Execute the Nmap command in the terminal
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            self.scan_results = result.stdout  # Store the command output
            print(self.scan_results)  # Display the results in the console
        except Exception as e:
            print(f"Error executing Nmap: {e}")  # Handle errors during command execution

    def _format_scan_results(self, nmap_scanner):
        """Format the Nmap scan results to make them readable."""
        result = "********************** Scan Report **********************\n"
        for host in nmap_scanner.all_hosts():  # Iterate over all scanned hosts
            result += f"\nHost: {host} | State: {nmap_scanner[host].state()}\n"
            for protocol in nmap_scanner[host].all_protocols():  # Iterate over protocols (TCP/UDP)
                result += f"\nProtocol: {protocol}\n"
                result += "Port\t\tState\t\tService\n"
                for port in nmap_scanner[host][protocol].keys():  # Iterate over scanned ports
                    name = nmap_scanner[host][protocol][port]['name']  # Service name
                    state = nmap_scanner[host][protocol][port]['state']  # Port state (open/closed)
                    result += f"{port}\t\t{state}\t\t{name}\n"  # Add port information to the result
        return result
