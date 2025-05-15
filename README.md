# Automatic Scan Tools

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.3-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

A comprehensive web vulnerability scanning toolkit featuring multiple scanning modules and a test environment, designed for security professionals and developers.

## Project Benefits Summary
This simple project offers several key advantages:

- Automated Vulnerability Detection: It enables simultaneous detection of multiple vulnerabilities, significantly increasing work efficiency.

- Report Generation: The project can generate a preliminary report, providing a foundation for consultants to enhance and finalize their findings.

- Enhanced Productivity: It assists security consultants in completing tests and report writing more quickly and conveniently.


## 📁 Project Structure
```
automatic_scan_tools/
├── app.py # Test web application with vulnerabilities
├── scanner.py # Main scanning engine
├── requirements.txt # Python dependencies
├── wordlists/ # Security testing payloads
│ ├── dirs.txt # Directory brute-forcing wordlist
│ └── payloads.txt # Vulnerability testing payloads
└── reports/ # Generated scan reports
```


## ✨ Features

### Multi-Module Scanning Engine
- **Directory Scanner**: Bruteforce common web paths (admin panels, config files)
- **SQL Injection Detector**: Test for database vulnerabilities
- **Custom Payload Support**: Extend with your own test cases
- **Concurrent Scanning**: Multi-threaded for performance

### Security Testing Environment
- **Built-in Vulnerable App**: Safe sandbox for testing
- **Multiple Vulnerability Types**: SQLi, exposed directories, and more
- **Realistic Responses**: Mimics production system behaviors

### Professional Reporting
- **Formatted Documents**: Microsoft Word report generation
- **Detailed Findings**: Vulnerability classification and evidence
- **Executive Summary**: Quick overview of security posture

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation
```bash
git clone https://github.com/yourusername/automatic_scan_tools.git
cd automatic_scan_tools
pip install -r requirements.txt
```

### Basic Usage
1.Start test server:
```bash
python app.py
```


2.Run full scan:

```bash
python scanner.py -u http://127.0.0.1:5000
```

3.View generated reports in reports/ directory

## 🛠️ Scanning Modules
### Directory Scanner
- Tests common web paths
- Customizable wordlist (wordlists/dirs.txt)
- Threaded implementation scans quickly
- Identifies exposed admin interfaces and sensitive files

### SQL Injection Detector
- Tests multiple injection techniques
- Supports GET/POST parameters
- Detects database errors and abnormal responses
