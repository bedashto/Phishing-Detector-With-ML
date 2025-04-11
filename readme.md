# ML-Based Phishing Detector

[![CI](https://github.com/bedashto/Phishing-Detector-With-ML/actions/workflows/phishing-detector-ci.yml/badge.svg)](https://github.com/bedashto/Phishing-Detector-With-ML/actions/workflows/phishing-detector-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

A comprehensive machine learning-based tool for detecting phishing attempts in both URLs and emails with enhanced functionality.

## Features

### URL Analysis Features
- **Machine Learning Classification**: Uses Random Forest algorithm to classify URLs as phishing or legitimate
- **Rich Feature Extraction**: Analyzes 20+ features from URLs and web page content
- **WHOIS Integration**: Checks domain registration information to identify newly created domains
- **HTML Content Analysis**: Examines website structure to detect suspicious elements like password fields
- **Batch Processing**: Ability to analyze multiple URLs from a file

### Email Analysis Features (New!)
- **Email Header Analysis**: Examines sender information, reply-to mismatches, and authentication headers
- **Content Inspection**: Identifies suspicious keywords and urgent language in email body and subject
- **URL Extraction**: Automatically extracts and analyzes all URLs contained in the email
- **HTML Analysis**: Detects forms, password fields, and other suspicious elements in HTML emails
- **Attachment Detection**: Flags emails with attachments as potentially suspicious
- **SPF/DKIM/DMARC Verification**: Checks for proper email authentication
- **Batch Processing**: Analyze entire directories of email files

### General Features
- **Command-Line Interface**: Easy-to-use CLI for training and prediction
- **Detailed Reporting**: Provides prediction confidence scores and feature breakdown
- **Model Management**: Save and load trained models for reuse
- **Comprehensive Logging**: Keeps detailed logs of all operations for auditing

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector

# Create and activate a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Dependencies

This project requires the following Python packages:
- pandas
- numpy
- scikit-learn
- beautifulsoup4
- requests
- python-whois
- tldextract
- joblib
- chardet

A full list of dependencies is available in the `requirements.txt` file.

## Usage

### Training a Model

#### For URL Detection:

```bash
python phishing_detector.py train --dataset path/to/url_dataset.csv --type url --output models/
```

#### For Email Detection:

```bash
python phishing_detector.py train --dataset path/to/email_dataset.csv --type email --output models/
```

The email dataset should contain columns `email_path` (path to email files) and `is_phishing` (1 for phishing, 0 for legitimate).

### Making Predictions

#### Analyze a single URL:

```bash
python phishing_detector.py url --url "https://example.com" --model models/
```

#### Analyze multiple URLs from a file:

```bash
python phishing_detector.py url --file urls.txt --output results.csv --model models/
```

#### Skip HTML content fetching (faster but less accurate):

```bash
python phishing_detector.py url --url "https://example.com" --no-fetch
```

#### Analyze a single email file:

```bash
python phishing_detector.py email --file path/to/email.eml --model models/
```

#### Analyze a directory of email files:

```bash
python phishing_detector.py email --directory path/to/emails/ --output results.csv --model models/
```

## Dataset Format

### URL Dataset Format

The URL training dataset should be a CSV file with at least these columns:
- `url`: The URL to analyze
- `is_phishing`: Binary label (1 for phishing, 0 for legitimate)

Example:
```
url,is_phishing
https://example.com,0
https://suspicious-site.com/login,1
```

### Email Dataset Format

The email training dataset should be a CSV file with at least these columns:
- `email_path`: Path to the email file (.eml format)
- `is_phishing`: Binary label (1 for phishing, 0 for legitimate)

Example:
```
email_path,is_phishing
data/emails/legitimate1.eml,0
data/emails/phishing1.eml,1
```

## Advanced Features

### URL Feature Extraction

The tool extracts the following URL features:
- URL length, domain length
- Number of dots, hyphens, underscores, digits
- HTTPS usage
- Domain age (via WHOIS)
- Presence of suspicious keywords
- Form, input, and password field counts
- External links count
- And many more

### Email Feature Extraction

The tool extracts the following email features:
- Header analysis (From, Reply-To, Subject)
- Sender domain and display name consistency
- Presence of authentication (SPF, DKIM, DMARC)
- Suspicious keywords in subject and body
- Urgent language detection
- Analysis of embedded URLs
- HTML content analysis
- Attachment detection
- Misspellings and brand impersonation detection

## Examples

### URL Analysis Example

```bash
python phishing_detector.py url --url "https://suspicious-bank-verify.com"
```

Output:
```
URL: https://suspicious-bank-verify.com
Status: PHISHING
Confidence: 0.92

Key Features:
- Suspicious words: 2
- HTTPS: No
- Domain age: 5 days
- Password fields: 1
```

### Email Analysis Example

```bash
python phishing_detector.py email --file phishing_email.eml
```

Output:
```
Email: phishing_email.eml
Status: PHISHING
Confidence: 0.89

Found 3 URLs in the email:
  1. https://malicious-site.com/login
  2. https://legitimate-bank.com
  3. https://tracking-pixel.com/pixel.gif

URL Analysis:
  - https://malicious-site.com/login: PHISHING (0.95)
  - https://legitimate-bank.com: LEGITIMATE (0.12)
  - https://tracking-pixel.com/pixel.gif: LEGITIMATE (0.35)

Key Email Features:
- Suspicious words in subject: 2
- Suspicious words in body: 5
- Reply-To mismatch detected
- Urgent language detected
- Sender display name does not match domain
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Do not use it for illegal activities. The authors are not responsible for any misuse or damage caused by this program.
