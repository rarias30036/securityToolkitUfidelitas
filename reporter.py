class Reporter:
    def __init__(self):
        # Initialize an empty list to store results
        self.results = []

    def add_result(self, tool_name, result):
        # Add a tuple containing the tool name and its result to the results list
        self.results.append((tool_name, result))

    def generate_report(self):
        try:
            # Open a file named 'security_report.txt' in write mode
            with open("security_report.txt", "w", encoding="utf-8") as file:
                file.write("********************** Security Report **********************\n")
                file.write("------------------------------------------------------------\n\n")

                # Loop through all results in the results list
                for tool_name, result in self.results:
                    # Write the tool name and its result to the file
                    file.write(f"=== {tool_name} ===\n")
                    file.write(f"{result}\n")
                    file.write("-" * 60 + "\n\n")  # Add a separator between tools

            print("\nSecurity report generated as 'security_report.txt'.")
        except Exception as e:
            print(f"\nError generating report: {e}")