# PII Detection & De-Identification Tool

A modern web-based application for detecting and de-identifying Personally Identifiable Information (PII) in various file formats.

## Features

- **Multi-format Support**: Process CSV, TXT, and PDF files
- **Pattern Configuration**: Use preset patterns or define custom regex patterns
- **Advanced De-identification**: Multiple masking strategies including partial mask, full mask, hashing, encryption, and redaction
- **Accuracy Metrics**: Comprehensive reporting with precision, recall, F1-score, and risk assessment
- **Modern Web UI**: Responsive design with drag-and-drop file upload
- **Real-time Processing**: Asynchronous file processing with progress indicators

## Supported PII Types

- Aadhaar Numbers
- PAN (Permanent Account Number)
- Credit Card Numbers
- Email Addresses
- Passport Numbers
- Driving License Numbers
- Phone Numbers
- Person Names

## Installation

1. Clone or download the repository
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Web Application (Recommended)

1. Start the Flask web server:
   ```bash
   python web_app.py
   ```

2. Open your browser and navigate to `http://localhost:5000`

3. Upload your file using the drag-and-drop interface or file browser

4. Configure detection patterns:
   - Choose between preset patterns or custom regex patterns
   - Select appropriate preset for your region (e.g., Indian Default)

5. Configure de-identification settings:
   - Enable/disable PII types
   - Choose masking strategy (partial, full, hash, encrypt, redact)
   - Set mask character
   - Optionally set expected counts for validation

6. Click "Run Detection" to process your file

7. View results in the Summary Report and Data Preview tabs

8. Download de-identified data and summary reports

### Desktop Application (Legacy)

For the desktop version using PySide6:
```bash
python app.py
```

## File Structure

```
ctspro/
├── web_app.py              # Flask web server
├── app.py                  # Desktop PySide6 application (legacy)
├── pii_utils.py            # Core PII detection utilities
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html         # Main web interface
├── static/
│   ├── css/
│   │   └── style.css      # Stylesheet
│   └── js/
│       └── app.js         # Frontend JavaScript
└── README.md              # This file
```

## Configuration Options

### Pattern Modes
- **Preset Patterns**: Pre-configured regex patterns optimized for different regions
- **Custom Patterns**: Define your own regex patterns for specific requirements

### De-identification Strategies
- **Partial Mask**: Mask only part of the sensitive data (e.g., `123****789`)
- **Full Mask**: Replace entire value with mask characters (e.g., `*********`)
- **Hash (SHA256)**: Replace with cryptographic hash
- **Encryption**: Encrypt the sensitive data (reversible)
- **Redact**: Remove the sensitive data entirely

### Risk Assessment
- **Low**: All found items were expected (Precision = 1.0)
- **Medium**: High precision (≥ 0.8), few false positives
- **High**: Moderate precision (≥ 0.5), some false positives
- **Critical**: Low precision (< 0.5) or found items when none expected

## API Endpoints

- `GET /` - Main web interface
- `GET /api/presets` - Get available pattern presets
- `GET /api/pii-types` - Get supported PII types and labels
- `POST /api/upload` - Upload and process file

## Security Considerations

- Files are processed in temporary storage and automatically cleaned up
- Sensitive data is only processed in memory during detection
- No persistent storage of uploaded files or processed data
- Use HTTPS in production environments
- Consider implementing authentication for sensitive deployments

## Browser Compatibility

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Performance

- Maximum file size: 16MB
- Supported concurrent users: Depends on server configuration
- Processing time: Varies based on file size and complexity

## Troubleshooting

### Common Issues

1. **PDF processing fails**: Ensure PyMuPDF is installed (`pip install PyMuPDF`)
2. **Large files timeout**: Consider increasing Flask timeout settings
3. **Memory issues**: Process smaller files or increase server memory

### Error Messages

- "No file uploaded": Select a file before running detection
- "Invalid file type": Only CSV, TXT, and PDF files are supported
- "PyMuPDF not installed": Install PyMuPDF for PDF support

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided as-is for educational and development purposes.

## Support

For issues and questions, please check the troubleshooting section or create an issue in the repository.
