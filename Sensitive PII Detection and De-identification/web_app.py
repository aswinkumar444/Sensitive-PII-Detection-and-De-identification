from flask import Flask, render_template, request, jsonify, send_file
import os
import csv
import json
import tempfile
from werkzeug.utils import secure_filename
from pii_utils import (
    detect_and_deidentify_record, get_preset_patterns,
    get_available_presets, PII_HANDLERS, PATTERN_PRESETS
)
import re
from typing import Dict, List, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

ALLOWED_EXTENSIONS = {'csv', 'txt', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_file(file_path, patterns, mask_configs, expected_counts):
    """Process uploaded file and return results"""
    try:
        headers, input_rows = [], []
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext == '.csv':
            headers, input_rows = read_csv(file_path)
        elif file_ext == '.txt':
            headers, input_rows = read_txt(file_path)
        elif file_ext == '.pdf':
            if fitz is None:
                raise ImportError("PyMuPDF is not installed. Please run 'pip install PyMuPDF' to process PDF files.")
            headers, input_rows = read_pdf(file_path)
        
        run_context = {}
        deidentified_rows = []
        summary = {"rows_processed": 0, "matches": {key: 0 for key in PII_HANDLERS}}
        
        for row in input_rows:
            deid_row, row_counts = detect_and_deidentify_record(row, patterns, mask_configs, context=run_context)
            deidentified_rows.append(deid_row)
            summary["rows_processed"] += 1
            for key in summary["matches"]:
                summary["matches"][key] += row_counts.get(key, 0)
        
        report_metrics = calculate_metrics(summary, expected_counts)
        
        return {
            'success': True,
            'headers': headers,
            'deidentified_rows': deidentified_rows,
            'summary': summary,
            'report_metrics': report_metrics
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def read_csv(file_path):
    with open(file_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        headers = next(reader, [])
        rows = list(reader)
    return headers, rows

def read_txt(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        rows = [[line.strip()] for line in f]
    return ["Text"], rows

def read_pdf(file_path):
    rows = []
    doc = fitz.open(file_path)
    for page in doc:
        for line in page.get_text().splitlines():
            if line.strip():
                rows.append([line.strip()])
    return ["Extracted Text"], rows

def calculate_metrics(summary, expected_counts):
    metrics = {}
    for key in PII_HANDLERS.keys():
        found = summary['matches'].get(key, 0)
        expected = expected_counts.get(key, None)
        tp = min(found, expected) if expected is not None else found
        fp = max(0, found - expected) if expected is not None else 0
        fn = max(0, expected - found) if expected is not None else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        risk_level = "N/A"
        if expected is not None:
            if tp == 0 and fp > 0:
                risk_level = "Critical"
            elif tp > 0 and fp == 0:
                risk_level = "Low"
            elif precision >= 0.8:
                risk_level = "Medium"
            elif precision >= 0.5:
                risk_level = "High"
            else:
                risk_level = "Critical"
        
        metrics[key] = {
            "found": found,
            "expected": expected,
            "tp": tp,
            "fp": fp,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "risk": risk_level
        }
    return metrics

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/presets')
def get_presets():
    return jsonify(get_available_presets())

@app.route('/api/pii-types')
def get_pii_types():
    pii_labels = {
        "aadhaar": "Aadhaar",
        "pan": "PAN",
        "credit_card": "Credit Card",
        "email": "Email",
        "passport": "Passport",
        "driving_license": "Driving License",
        "phone": "Phone",
        "person": "Name"
    }
    return jsonify({
        'types': list(PII_HANDLERS.keys()),
        'labels': pii_labels
    })

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get configuration from request
        config = json.loads(request.form.get('config', '{}'))
        
        # Process patterns
        patterns = {}
        if config.get('use_preset', True):
            preset_name = config.get('preset', 'Indian (Default)')
            # Use preset patterns (empty dict means use defaults)
        else:
            # Compile custom patterns
            custom_patterns = config.get('custom_patterns', {})
            for key, pattern_text in custom_patterns.items():
                if pattern_text.strip():
                    try:
                        patterns[key] = re.compile(pattern_text)
                    except re.error:
                        continue
        
        # Process mask configurations
        mask_configs = {}
        mask_config_data = config.get('mask_configs', {})
        strategy_map = {
            "partial": "partial",
            "full": "full", 
            "hash": "hash",
            "encrypt": "encrypt",
            "redact": "redact"
        }
        
        for key in PII_HANDLERS.keys():
            key_config = mask_config_data.get(key, {})
            mask_configs[key] = {
                'enabled': key_config.get('enabled', True),
                'strategy': strategy_map.get(key_config.get('strategy', 'partial'), 'partial'),
                'char': key_config.get('char', '*')
            }
        
        # Process expected counts
        expected_counts = {}
        expected_data = config.get('expected_counts', {})
        for key, value in expected_data.items():
            if value and str(value).isdigit():
                expected_counts[key] = int(value)
            else:
                expected_counts[key] = None
        
        # Process the file
        result = process_file(file_path, patterns, mask_configs, expected_counts)
        
        # Clean up uploaded file
        try:
            os.remove(file_path)
        except:
            pass
        
        return jsonify(result)
    
    return jsonify({'success': False, 'error': 'Invalid file type'})

@app.route('/api/download/<data_type>')
def download_data(data_type):
    # This would need to be implemented with session storage or database
    # For now, return an error
    return jsonify({'success': False, 'error': 'Download functionality requires session storage'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
