from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
import os
import hashlib
import subprocess
import json
import magic  # For MIME type detection

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
REPORT_FOLDER = 'reports'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(REPORT_FOLDER):
    os.makedirs(REPORT_FOLDER)

def file_integrity_check(file_path):
    """ Check file integrity using SHA-256 hash. """
    file_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            file_hash.update(chunk)
    return file_hash.hexdigest()

def virus_malware_scan(file_path):
    """ Scan file for malware using ClamAV. """
    result = subprocess.run(['clamscan', file_path], capture_output=True, text=True)
    return 'Infected' in result.stdout

def metadata_analysis(file_path):
    """ Extract and analyze metadata from file. """
    # Using the `file` command from `libmagic` library
    mime_type = magic.from_file(file_path, mime=True)
    return {'mime_type': mime_type}

def file_type_validation(file_path):
    """ Validate file type by checking its MIME type. """
    mime_type = magic.from_file(file_path, mime=True)
    return mime_type

def network_activity_monitoring():
    """ Placeholder for network activity monitoring logic. """
    # Implement network monitoring logic or use a tool like Wireshark/tcpdump
    return {"status": "No suspicious activity detected"}

def log_analysis():
    """ Analyze system logs for abnormal patterns. """
    # Placeholder for log analysis
    return {"status": "Logs are clean"}

def generate_report(file_name, results):
    """ Generate a report file with scan results. """
    report_path = os.path.join(app.config['REPORT_FOLDER'], f'{file_name}_report.json')
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=4)
    return report_path

@app.route('/scan_file', methods=['POST'])
def scan_file():
    file_path = request.form['file_path']
    scan_type = request.form['scan_type']

    results = {'file': file_path}
    if scan_type == 'file_integrity':
        results['integrity'] = file_integrity_check(file_path)
    elif scan_type == 'virus_malware':
        results['virus_malware'] = virus_malware_scan(file_path)
    elif scan_type == 'metadata_analysis':
        results['metadata'] = metadata_analysis(file_path)
    elif scan_type == 'file_type_validation':
        results['file_type'] = file_type_validation(file_path)
    elif scan_type == 'network_activity':
        results['network_activity'] = network_activity_monitoring()
    elif scan_type == 'log_analysis':
        results['log_analysis'] = log_analysis()

    report_path = generate_report(file_path, results)
    return redirect(url_for('view_report', filename=os.path.basename(report_path)))

@app.route('/automated_scan', methods=['POST'])
def automated_scan():
    files = request.form.getlist('files')
    results = {}

    for file_name in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
        results[file_name] = {
            'integrity': file_integrity_check(file_path),
            'virus_malware': virus_malware_scan(file_path),
            'metadata': metadata_analysis(file_path),
            'file_type': file_type_validation(file_path),
            'network_activity': network_activity_monitoring(),
            'log_analysis': log_analysis()
        }
        generate_report(file_name, results[file_name])

    return redirect(url_for('view_report', filename='automated_scan_report.json'))

@app.route('/view_report/<filename>')
def view_report(filename):
    return send_from_directory(app.config['REPORT_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
