import socket
import concurrent.futures
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Common service names for well-known ports
SERVICE_MAP = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS-SSN", 143: "IMAP", 443: "HTTPS", 445: "Microsoft-DS",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

def scan_port(ip, port, timeout=1.0):
    """Attempt to connect to ip:port. Return (port, is_open, service)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = SERVICE_MAP.get(port, "Unknown")
                return port, True, service
    except Exception:
        pass
    return port, False, None

@app.route('/')
def index():
    # Simple HTML page embedded in the Flask app
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    ip = data.get('ip', '').strip()
    start_port = data.get('start_port')
    end_port = data.get('end_port')

    # Validate input
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
    try:
        start_port = int(start_port)
        end_port = int(end_port)
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid port range'}), 400

    # Validate IP format (basic check)
    try:
        socket.inet_aton(ip)
    except socket.error:
        return jsonify({'error': 'Invalid IP address format'}), 400

    ports = range(start_port, end_port + 1)
    results = []

    # Use thread pool for faster scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service = future.result()
            if is_open:
                results.append({
                    'port': port,
                    'status': 'Open',
                    'service': service
                })
            else:
                results.append({
                    'port': port,
                    'status': 'Closed',
                    'service': ''
                })

    # Sort results by port number
    results.sort(key=lambda x: x['port'])
    return jsonify({'results': results})

# HTML template (embedded as a string)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>IP Port Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 800px; margin: auto; }
        input, button { padding: 8px; margin: 5px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .open { color: green; font-weight: bold; }
        .closed { color: gray; }
        #exportBtn { display: none; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IP Port Scanner</h1>
        <div>
            <label>Target IP:</label>
            <input type="text" id="ip" placeholder="e.g., 127.0.0.1" value="127.0.0.1">
            <label>Port Range:</label>
            <input type="number" id="startPort" value="1" min="1" max="65535">
            <span>to</span>
            <input type="number" id="endPort" value="1024" min="1" max="65535">
            <button onclick="startScan()">Scan</button>
        </div>
        <div id="status"></div>
        <table id="resultsTable">
            <thead>
                <tr><th>Port</th><th>Status</th><th>Service</th></tr>
            </thead>
            <tbody></tbody>
        </table>
        <button id="exportBtn" onclick="exportCSV()">Export Results</button>
    </div>

    <script>
        let scanResults = [];

        async function startScan() {
            const ip = document.getElementById('ip').value.trim();
            const startPort = parseInt(document.getElementById('startPort').value);
            const endPort = parseInt(document.getElementById('endPort').value);
            const statusDiv = document.getElementById('status');
            const tableBody = document.querySelector('#resultsTable tbody');
            const exportBtn = document.getElementById('exportBtn');

            if (!ip || isNaN(startPort) || isNaN(endPort) || startPort > endPort) {
                statusDiv.textContent = 'Please enter valid IP and port range.';
                return;
            }

            statusDiv.textContent = 'Scanning... This may take a moment.';
            tableBody.innerHTML = '';
            exportBtn.style.display = 'none';
            scanResults = [];

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, start_port: startPort, end_port: endPort })
                });
                const data = await response.json();
                if (data.error) { 
                    statusDiv.textContent = 'Error: ' + data.error;
                    return;
                }
                scanResults = data.results;
                displayResults(scanResults);
                statusDiv.textContent = `Scan complete. ${scanResults.filter(r => r.status === 'Open').length} open ports found.`;
                exportBtn.style.display = 'inline-block';
            } catch (err) {
                statusDiv.textContent = 'Failed to scan: ' + err.message;
            }
        }

        function displayResults(results) {
            const tableBody = document.querySelector('#resultsTable tbody');
            tableBody.innerHTML = '';
            results.forEach(result => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${result.port}</td>
                    <td class="${result.status.toLowerCase()}">${result.status}</td>
                    <td>${result.service || ''}</td>
                `;
                tableBody.appendChild(row);
            });
        }

        function exportCSV() {
            if (scanResults.length === 0) return;
            let csv = 'Port,Status,Service\\n';
            scanResults.forEach(r => {
                csv += `${r.port},${r.status},${r.service || ''}\\n`;
            });
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'scan_results.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)