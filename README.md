# LangGraph CyberSecurity Agent

![Security Shield](https://img.shields.io/badge/Security-Enhanced-blue)
![Python](https://img.shields.io/badge/Python-3.11+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

A comprehensive cybersecurity solution built using LangGraph, a powerful framework for constructing stateful, multi-agent applications with Large Language Models (LLMs). This agent serves as your security sentinel, continuously monitoring and protecting your systems against potential threats.

## ✨ Features

- **🔍 Vulnerability Scanning**: Detects potential security weaknesses in your infrastructure using integrated tools
- **📊 System Monitoring**: Continuously monitors system activities to identify suspicious behavior in real-time
- **🤖 Multi-Agent Coordination**: Employs multiple specialized agents working in unison to enhance cybersecurity measures
- **📝 Comprehensive Reporting**: Generates detailed reports on security findings and recommended actions
- **🔄 Automated Remediation**: Suggests and (when configured) implements security fixes for detected vulnerabilities

## 🛠️ Installation

### Prerequisites

- python33.8 or higher
- Access to necessary API keys (configured in environment variables)
- Security tools: nmap, gobuster, ffuf, sqlmap

### Security Tools Installation

#### Installing Nmap

**On Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install nmap
```

**On macOS (using Homebrew):**
```bash
brew install nmap
```

**On Windows:**
1. Download the installer from the [Nmap official website](https://nmap.org/download.html)
2. Run the installer and follow the installation wizard
3. Verify installation: `nmap --version`

#### Installing Gobuster

**On Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install gobuster
```

**Using Go (cross-platform):**
```bash
go install github.com/OJ/gobuster/v3@latest
```

**On macOS (using Homebrew):**
```bash
brew install gobuster
```

#### Installing ffuf (Fast Web Fuzzer)

**Using Go (recommended for all platforms):**
```bash
go install github.com/ffuf/ffuf@latest
```

**Verify installation:**
```bash
ffuf -V
```

#### Installing SQLMap

**On Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install sqlmap
```

**On macOS (using Homebrew):**
```bash
brew install sqlmap
```

**Using Python (cross-platform):**
```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python3 sqlmap.py --version
```

#### Verifying Tool Installations

After installing all tools, verify they're correctly installed and available in your PATH:

```bash
# Check versions
nmap --version
gobuster --version
ffuf -V
sqlmap --version
```

### Setup

1. **Clone the Repository:**

```bash
git clone https://github.com/Vansh41104/LangGraph_CyberSecurity_Agent.git
cd LangGraph_CyberSecurity_Agent
```

2. **Set Up a Virtual Environment:**

```bash
python3 -m venv venv
venv\Scripts\activate
```

3. **Install Dependencies:**

```bash
pip install -r requirements.txt
```

4. **Configure Environment Variables:**

Create a `.env` file in the root directory using the template below:

```
GROQ_API_KEY=your_groq_api_key_here
DEFAULT_DOMAINS=google.com
DEFAULT_IP_RANGES=192.168.1.0/24

# Tool configurations
NMAP_PATH=/usr/bin/nmap
GOBUSTER_PATH=/usr/bin/gobuster
FFUF_PATH=/usr/bin/ffuf
SQLMAP_PATH=/usr/bin/sqlmap

# Scan settings
MAX_TASK_RETRIES=3
TASK_TIMEOUT=300  # seconds

# Logging settings
LOG_LEVEL=INFO
LOG_FILE=pipeline.log
```

## 🚀 Usage

### Basic Usage

Run the main script to start the cybersecurity agent:

```bash
python3 main.py -t "Scan <Domain Name> for open ports" -d <Domain Name>
```

### Running Examples

The project includes example scripts that demonstrate various functionalities:

```bash
sh run_examples.sh
```

### Streamlit Interface

For a more interactive experience, launch the Streamlit application:

```bash
python3 main.py --streamlit
```

This provides a web-based GUI for interacting with the agent, viewing scan results, and configuring security policies.

## 📂 Project Structure

```
LangGraph_CyberSecurity_Agent/
├── .env                     # Environment variables configuration
├── .gitignore               # Git ignore file
├── debug/                   # Debug information and logs
├── langraph/                # LangGraph core components
│   ├── __pycache__/         # python3 cache directory
│   └── workflow.py          # Main workflow definition
├── logs/                    # Log files directory
├── main.py                  # Application entry point
├── LICENSE                  # MIT License file
├── README.md                # Project documentation
├── requirements.txt         # Project dependencies
├── run_examples.sh          # Script to run example implementations
├── pytest_cache/            # Pytest cache directory
├── scan/                    # Scanning modules
│   ├── __pycache__/         # python3 cache directory
│   └── nmap_scan.py         # Nmap scanning implementation
├── streamlit_app/           # Interactive web interface
│   └── app.py               # Streamlit application
├── tests/                   # Test suite
│   ├── __pycache__/         # python3 cache directory
│   ├── test_scope.py        # Tests for scope functionality
│   └── test_task_manager.py # Tests for task manager functionality
├── utils/                   # Utility functions
│   ├── __pycache__/         # python3cache directory
│   ├── retry.py             # Retry mechanism for failed operations
│   ├── scope.py             # Scope definition utilities
│   └── task_manager.py      # Task management functionality
└── venv/                    # Virtual environment directory
    └── ...                  # Virtual environment files
```

## 🔧 Configuration Options

The agent can be configured through environment variables or a `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | API key for GROQ services | None |
| `DEFAULT_DOMAINS` | Comma-separated list of domains to monitor | google.com |
| `DEFAULT_IP_RANGES` | CIDR notation of IP ranges to scan | 192.168.1.0/24 |
| `NMAP_PATH` | Path to the Nmap executable | /usr/bin/nmap |
| `GOBUSTER_PATH` | Path to the Gobuster executable | /usr/bin/gobuster |
| `FFUF_PATH` | Path to the ffuf executable | /usr/bin/ffuf |
| `SQLMAP_PATH` | Path to the SQLMap executable | /usr/bin/sqlmap |
| `MAX_TASK_RETRIES` | Maximum number of retry attempts for failed tasks | 3 |
| `TASK_TIMEOUT` | Timeout for tasks in seconds | 300 |
| `LOG_LEVEL` | Logging verbosity (DEBUG, INFO, WARNING, ERROR) | INFO |
| `LOG_FILE` | Path to log file | pipeline.log |

## 💻 Key Components

- **workflow.py**: Defines the LangGraph workflow for coordinating cybersecurity tasks
- **nmap_scan.py**: Implements network scanning functionality using Nmap
- **task_manager.py**: Manages the execution and monitoring of cybersecurity tasks
- **retry.py**: Provides resilient operation with automatic retries for transient failures
- **scope.py**: Defines the scope of security scanning operations

## 🧪 Testing

Run the test suite to ensure all components are functioning correctly:

```bash
# Run all tests
python3 -m pytest tests/

# Run specific tests
python3 -m pytest tests/test_task_manager.py::TestTask -v
python3 -m pytest tests/test_scope.py -v
```

## 📈 Performance Considerations

- For large networks, increase `TASK_TIMEOUT` to allow for complete scanning
- Set `LOG_LEVEL` to DEBUG for troubleshooting but revert to INFO for production use
- Consider hardware requirements based on network size and scanning frequency

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.