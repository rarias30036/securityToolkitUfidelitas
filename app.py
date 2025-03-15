from flask import Flask, render_template, request, redirect, url_for
from main import SecurityToolkit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'  # Secret key for session management

toolkit = SecurityToolkit()  # Initialize the security toolkit

@app.route('/')
def index():
    return render_template('index.html')  # Render the main page

@app.route('/port_scan', methods=['POST'])
def port_scan():
    target = request.form['target']  # Get target IP/hostname from form
    toolkit.port_scanner.autoScan(target)  # Perform auto port scan
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/custom_nmap_scan', methods=['POST'])
def custom_nmap_scan():
    command = request.form['command']  # Get custom Nmap command from form
    toolkit.port_scanner.scan_with_nmap(command)  # Execute custom Nmap command
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/traffic_analyzer', methods=['POST'])
def traffic_analyzer():
    toolkit.traffic_analyzer.analyze_traffic()  # Start network traffic analysis
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/stop_traffic_analysis', methods=['POST'])
def stop_traffic_analysis():
    toolkit.traffic_analyzer.stop_analysis()  # Stop network traffic analysis
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/penetration_test', methods=['POST'])
def penetration_test():
    url = request.form['url']  # Get URL to test from form
    toolkit.penetration_tester.test_website(url)  # Perform penetration testing
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/stop_penetration_test', methods=['POST'])
def stop_penetration_test():
    toolkit.penetration_tester.stop_test()  # Stop penetration testing
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/system_protection', methods=['POST'])
def system_protection():
    ip = request.form['ip']  # Get IP address from form
    action = request.form['action']  # Get action (block/unblock) from form
    if action == 'block':
        toolkit.system_protector.block_ip(ip)  # Block the IP
    elif action == 'unblock':
        toolkit.system_protector.unblock_ip(ip)  # Unblock the IP
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/list_blocked_ips', methods=['POST'])
def list_blocked_ips():
    toolkit.system_protector.list_blocked_ips()  # List all blocked IPs
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/web_traffic_monitor', methods=['POST'])
def web_traffic_monitor():
    toolkit.web_traffic_monitor.monitor_http_traffic()  # Start HTTP traffic monitoring
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/stop_web_traffic_monitor', methods=['POST'])
def stop_web_traffic_monitor():
    toolkit.web_traffic_monitor.stop_monitoring()  # Stop HTTP traffic monitoring
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/web_scraping', methods=['POST'])
def web_scraping():
    scrape_url = request.form['scrape_url']  # Get URL to scrape from form
    toolkit.web_traffic_monitor.perform_web_scraping(scrape_url)  # Perform web scraping
    return redirect(url_for('index'))  # Redirect back to the main page

@app.route('/generate_report', methods=['POST'])
def generate_report():
    toolkit.reporter.generate_report()  # Generate a security report
    return redirect(url_for('index'))  # Redirect back to the main page

if __name__ == '__main__':
    app.run(debug=True)  # Run the Flask app in debug mode