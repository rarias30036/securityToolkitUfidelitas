class Reporter:
    def __init__(self):
        self.results = []

    def add_result(self, tool_name, result):
        self.results.append((tool_name, result))
        print(f"Result added: {tool_name}")

    def generate_report(self):
        try:
            with open("security_report.txt", "w", encoding="utf-8") as file:
                file.write("********************** Security Report **********************\n")
                file.write("------------------------------------------------------------\n\n")
                for tool_name, result in self.results:
                    file.write(f"=== {tool_name} ===\n")
                    file.write(f"{result}\n")
                    file.write("-" * 60 + "\n\n")
            print("Report generated as 'security_report.txt'.")
        except Exception as e:
            print(f"Error generating report: {e}")