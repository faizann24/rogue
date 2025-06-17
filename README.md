<p align="center">
  <img src="logo/logo.png" alt="Rogue Logo" width="270"/>
</p>

# Rogue 🎯
> An intelligent web vulnerability scanner agent powered by Large Language Models

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Rogue is an advanced AI security testing agent that leverages Large Language Models to intelligently discover and validate web application vulnerabilities. Unlike traditional scanners that follow predefined patterns, Rogue thinks like a human penetration tester - analyzing application behavior, generating sophisticated test cases, and validating findings through autonomous decision making.

Note: This is a very early release with many planned improvements and features still in development. Open source contributions are most welcome.

<p align="center">
  <img src="logo/demo.gif" alt="Demo GIF"/>
</p>

## 🌟 Key Features

- **Intelligent Vulnerability Discovery**: Uses LLMs to understand application context and identify potential security weaknesses
- **Iterative Planning**: Generates security tests in batches, learning from execution results to improve subsequent plans
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
python run.py -u https://example.com -e -s -m o3-mini -i 10

# Unlimited plans with contextual intelligence
python run.py -u https://example.com -p -1 -i 5
```

## 🛠️ Command Line Options

### Required Parameters
| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url` | Target URL to test (required) | `-u https://example.com` |

### Security Testing Configuration
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-p, --num-plans` | Number of security test plans per page | `10` | `-p 15` (specific count)<br>`-p -1` (unlimited) |
| `-i, --max-iterations` | Maximum iterations per security plan | `10` | `-i 5` (quick scan)<br>`-i 20` (thorough) |
| `--disable-rag` | Disable RAG knowledge fetching for faster startup | `false` | `--disable-rag` |
| `--disable-iterative` | Disable iterative planning and use legacy mode (all plans generated at once) | `false` | `--disable-iterative` |
| `-m, --model` | LLM model for analysis | `o4-mini` | `-m o3-mini`<br>`-m o1-preview` |

### Scope and Discovery
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-e, --expand` | Test discovered URLs recursively | `False` | `-e` (enable expansion) |
| `-s, --subdomains` | Enumerate and test subdomains | `False` | `-s` (enable subdomain discovery) |

### Output and Reporting
| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-o, --output` | Directory for scan results | `security_results` | `-o my_scan_results` |

## 📋 Usage Examples

```bash
# Quick security assessment (5 plans, 3 iterations each)
python run.py -u https://example.com -p 5 -i 3

# Standard comprehensive scan with iterative planning (default)
python run.py -u https://example.com -p 10 -i 10

# Legacy mode - all plans generated at once (faster startup)
python run.py -u https://example.com -p 10 -i 10 --disable-iterative

# Unlimited plans with iterative learning (15-25+ adaptive plans)
python run.py -u https://example.com -p -1 -i 5

# Unlimited plans in legacy mode (generates many plans upfront)
python run.py -u https://example.com -p -1 -i 5 --disable-iterative

# Deep security audit with scope expansion and iterative planning
python run.py -u https://example.com -p -1 -i 10 -e -s

# Fast startup with disabled RAG and legacy planning
python run.py -u https://example.com -p 5 -i 3 --disable-rag --disable-iterative

# Targeted research with advanced model and iterative planning
python run.py -u https://example.com -p 20 -i 15 -m o1-preview

# Custom output directory with subdomain enumeration
python run.py -u https://example.com -s -o "results/$(date +%Y%m%d)" -p -1
```

## 🎯 Security Testing Modes

### Plan Generation Strategies

**Limited Plans (`-p <number>`)**
- Generates a specific number of focused security test plans
- Best for: Quick assessments, time-constrained testing
- Example: `-p 5` generates 5 targeted vulnerability tests

**Unlimited Plans (`-p -1`)**
- Generates comprehensive security test coverage (15-25+ plans)
- Includes contextual CVE intelligence based on detected technologies
- Best for: Thorough security audits, research, bug bounty hunting
- Example: `-p -1` generates maximum coverage plans

### Iteration Control

**Quick Scan (`-i 3-5`)**
- Fast vulnerability discovery
- Surface-level testing
- Good for initial reconnaissance

**Standard Scan (`-i 8-12`)**
- Balanced depth and speed
- Recommended for most use cases
- Thorough validation of findings

**Deep Scan (`-i 15-20`)**
- Exhaustive testing per vulnerability
- Maximum exploitation attempts
- Best for critical applications

### Model Selection

**o4-mini (Default)**
- Fast and cost-effective
- Good for standard web application testing
- Balanced performance and accuracy

**o3-mini**
- Enhanced reasoning capabilities
- Better for complex applications
- Improved payload generation

**o1-preview**
- Advanced analytical capabilities
- Best for sophisticated targets
- Maximum accuracy and depth

## 🧠 Advanced Features

### Iterative Planning vs Legacy Mode

**Iterative Planning (Default)**
- Plans are generated in batches that learn from previous execution results
- For fixed plans: divided into 3 batches (33% each, max 3 batches)  
- For unlimited plans (-p -1): generated in batches of 5 (max 5 batches = 25 plans)
- Each batch uses insights from previous plan executions to generate more targeted tests
- Adaptive learning improves success rates and reduces redundant testing

**Legacy Mode (--disable-iterative)**
- All plans generated upfront in a single batch
- No learning between plan executions
- Faster initial planning but potentially less targeted testing
- Useful for consistent, reproducible test scenarios

### Contextual Intelligence
- **Technology Detection**: Automatically identifies frameworks, CMS, libraries
- **CVE Integration**: Fetches relevant vulnerabilities from CISA KEV catalog
- **Smart Targeting**: Focuses tests on detected technologies

### Traffic Analysis
- **Request Monitoring**: Captures all HTTP/HTTPS traffic
- **Response Analysis**: Analyzes server responses for vulnerabilities
- **Session Tracking**: Maintains authentication state

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

## 📋 TODOs

- [ ] Add support for Anthropic Claude models
- [ ] Integrate vision API capabilities for visual analysis
- [ ] Run against HackerOne reports to find first LLM-powered vulnerability in the wild
- [ ] Implement more sophisticated planning algorithms
- [ ] Add better execution strategies and error handling
- [ ] Support for custom LLM model deployment
- [ ] Add collaborative testing capabilities
- [ ] Improve subdomain enumeration techniques
- [ ] Add API security testing capabilities
- [x] ~~Add basic documentation and examples~~


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
