<p align="center">
  <img src="logo/logo.png" alt="Rogue Logo" width="400"/>
</p>

# Rogue 🎯
> An intelligent web vulnerability scanner powered by Large Language Models

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Rogue is an advanced security testing tool that leverages Large Language Models to intelligently discover and validate web application vulnerabilities. Unlike traditional scanners that follow predefined patterns, Rogue thinks like a human penetration tester - analyzing application behavior, generating sophisticated test cases, and validating findings.

## 🌟 Key Features

- **Intelligent Vulnerability Discovery**: Uses LLMs to understand application context and identify potential security weaknesses
- **Advanced Payload Generation**: Creates sophisticated test payloads tailored to the target application
- **Context-Aware Testing**: Analyzes application behavior and responses to guide testing strategy
- **Automated Exploit Verification**: Validates findings to eliminate false positives
- **Comprehensive Reporting**: Generates detailed vulnerability reports with reproduction steps
- **Subdomain Enumeration**: Optional discovery of related subdomains
- **Traffic Monitoring**: Built-in proxy captures and analyzes all web traffic
- **Expandable Scope**: Option to recursively test discovered URLs

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- OpenAI API key
- Playwright

### Installation

```bash
# Clone the repository
git clone https://github.com/faizann24/rogue
cd rogue

# Install dependencies
pip install -r requirements.txt

# Set up your OpenAI API key
export OPENAI_API_KEY='your-api-key-here'
```

### Basic Usage

```bash
# Basic scan of a single URL
python run.py -u https://example.com

# Advanced scan with subdomain enumeration and URL discovery
python run.py -u https://example.com -e -s -m o3-preview -i 10
```

## 🛠️ Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL to test (required) |
| `-e, --expand` | Expand testing to discovered URLs |
| `-s, --subdomains` | Perform subdomain enumeration |
| `-m, --model` | LLM model to use (o3-mini or o1-preview) |
| `-o, --output` | Output directory for results |
| `-i, --max-iterations` | Maximum iterations per plan of attack |

## 🏗️ Architecture

Rogue is built with a modular architecture consisting of several key components:

- **Agent**: Orchestrates the scanning process and manages other components
- **Planner**: Generates intelligent testing strategies using LLMs
- **Scanner**: Handles web page interaction and data collection
- **Proxy**: Monitors and captures network traffic
- **Reporter**: Analyzes findings and generates detailed reports
- **Tools**: Collection of testing and exploitation tools

## 📊 Example Report

Reports are generated in both text and markdown formats, containing:

- Executive summary
- Detailed findings with severity ratings
- Technical details and reproduction steps
- Evidence and impact analysis
- Remediation recommendations

## 🔒 Security Considerations

- Always obtain proper authorization before testing
- Use responsibly and ethically
- Follow security testing best practices
- Be mindful of potential impact on target systems

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the GPL3 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for security professionals and researchers. Always obtain proper authorization before testing any systems you don't own. The authors are not responsible for any misuse or damage caused by this tool.

## 🙏 Acknowledgments

- OpenAI for their powerful language models
- Playwright for web automation capabilities
- The security research community for inspiration and guidance

## 📧 Contact

For questions, feedback, or issues, please:
- Open an issue in this repository
- Contact the maintainers at [faizann288@gmail.com]

---
Made with ❤️ by Faizan
