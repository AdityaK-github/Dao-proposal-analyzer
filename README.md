# 🛡️ DAO Guardian - Smart Contract & Proposal Security Analyzer

**AI-powered security analysis for DAO proposals and smart contracts**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🌟 Overview

DAO Guardian is an intelligent security analysis tool that helps DAO members and developers assess:

- 📊 **DAO Proposals** - Analyze governance proposals from Snapshot
- 🔒 **Smart Contracts** - Scan Ethereum contracts for vulnerabilities
- 🤖 **AI-Powered** - Uses Groq LLM (Llama 3.3 70B) for deep analysis
- 🎯 **Real-time** - Fetch live data from Snapshot and Etherscan APIs

## ✨ Features

### 📊 Proposal Analysis

- Fetch proposals directly from Snapshot
- AI-generated risk assessments
- Governance insights and recommendations
- Author and DAO metadata extraction

### 🔐 Smart Contract Security Scanning

- **20+ vulnerability patterns** covering:

  - 🔄 Reentrancy Attacks
  - 🔐 Access Control Issues
  - ⚠️ Error Handling Problems
  - 💥 Contract Destruction Risks
  - 🎲 Randomness & Time Manipulation
  - ➕ Arithmetic Vulnerabilities
  - 💾 Storage Issues
  - ✨ Code Quality & Best Practices
  - 🚫 Denial of Service
  - ⛔ Deprecated Functions
  - 📝 Missing Events
  - 🔄 State Variable Issues

- **Detailed Reports** with:

  - Line numbers and code snippets
  - Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
  - Category grouping
  - Expert recommendations
  - Security grading (A-F)
  - One-click example contracts

- **Input Validation** with:
  - Format checking (hex, length)
  - Helpful error messages
  - Auto-correction suggestions

### 🎨 Interactive Frontend

- Beautiful Streamlit web interface
- Real-time analysis
- Categorized vulnerability display
- Comprehensive risk assessments

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- API keys:
  - [Groq API Key](https://console.groq.com/) (for AI analysis)
  - [Etherscan API Key](https://etherscan.io/apis) (for contract scanning)

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/AdityaK-github/Dao-proposal-analyzer.git
cd Dao-proposal-analyzer
```

2. **Create virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
.\venv\Scripts\activate  # On Windows
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Configure API keys**

```bash
cp .env.example .env
# Edit .env and add your API keys
```

### Running the App

```bash
streamlit run frontend_app.py
```

Then open your browser to `http://localhost:8501`

---

## 🔧 Configuration

Create a `.env` file in the root directory:

```env
GROQ_API_KEY=your_groq_api_key_here
ETHERSCAN_API_KEY=your_etherscan_api_key_here
```

---

## 📖 Usage

### 1. Analyze a DAO Proposal

1. Select **"📊 Proposal Analysis"** mode
2. Enter a Snapshot proposal ID (e.g., `0xf06f3ad61f9f77c8ed362dd54913cc44d030841eebebfffce4dd6605b1b0e6f3`)
3. Click **"🔍 Analyze Proposal"**
4. Review the AI-generated analysis and risk score

### 2. Scan a Smart Contract

1. Select **"🔒 Contract Security"** mode
2. Enter an Ethereum contract address (e.g., `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`)
3. Click **"🔍 Scan Contract"**
4. Review vulnerabilities grouped by category

### 3. Complete Analysis

1. Select **"🎯 Complete Analysis"** mode
2. Enter both proposal ID and contract address
3. Click **"🚀 Run Complete Analysis"**
4. Get comprehensive security assessment with final recommendations

---

## 🏗️ Architecture

```
┌─────────────────┐
│  Streamlit UI   │  ← User Interface
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│ analysis_functions  │  ← Core Logic
└────────┬────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌─────────┐ ┌──────────┐
│Snapshot │ │Etherscan │  ← External APIs
│ GraphQL │ │   API    │
└─────────┘ └──────────┘
         │
         ▼
    ┌─────────┐
    │ Groq AI │  ← LLM Analysis
    └─────────┘
```

### Project Structure

```
Dao-proposal-analyzer/
├── frontend_app.py          # Streamlit web interface
├── analysis_functions.py    # Core analysis logic
├── requirements.txt         # Python dependencies
├── .env.example            # Environment template
├── .gitignore              # Git ignore rules
├── README.md               # This file
└── IMPROVEMENTS_LOG.md     # Development log
```

---

## 🔍 Vulnerability Detection

The system detects 16 types of vulnerabilities:

| Category             | Patterns | Severity Range |
| -------------------- | -------- | -------------- |
| Reentrancy Attacks   | 1        | HIGH           |
| Access Control       | 4        | HIGH-MEDIUM    |
| Error Handling       | 2        | HIGH-MEDIUM    |
| Contract Destruction | 1        | CRITICAL       |
| Randomness & Time    | 2        | MEDIUM-LOW     |
| Arithmetic           | 1        | HIGH           |
| Storage Issues       | 1        | HIGH           |
| Code Quality         | 2        | LOW            |
| Input Validation     | 1        | LOW            |
| Deprecated Functions | 1        | HIGH           |
| Denial of Service    | 1        | MEDIUM         |

Each vulnerability includes:

- Detailed description
- Specific line numbers
- Code context
- Security recommendations
- Severity classification

---

## 🧪 Testing

Test with these example contracts:

**Stablecoins:**

- USDC: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- DAI: `0x6B175474E89094C44Da98b954EedeAC495271d0F`

**Example Proposals:**

- ENS: `0xf06f3ad61f9f77c8ed362dd54913cc44d030841eebebfffce4dd6605b1b0e6f3`

---

## 🛠️ Technology Stack

- **Frontend**: Streamlit
- **Backend**: Python 3.8+
- **AI**: Groq (Llama 3.3 70B Versatile)
- **APIs**: Snapshot GraphQL, Etherscan
- **Analysis**: Pattern matching + AI reasoning

---

## 📊 Example Output

### Vulnerability Report

```
Security Grade: C
Total Issues: 5

Access Control (2 issues)
  🟠 Unprotected Function (Line 42) - MEDIUM
  🟡 tx.origin Authentication (Line 15) - MEDIUM

Reentrancy Attacks (1 issue)
  🟠 Reentrancy (Line 67) - HIGH

Code Quality (2 issues)
  🟢 Floating Pragma (Line 1) - LOW
  🟢 Block Timestamp (Line 89) - LOW
```

---

## 🤝 Contributing

Contributions welcome! To add new vulnerability patterns:

1. Edit `analysis_functions.py`
2. Add pattern to the `patterns` dictionary
3. Include: pattern, severity, category, description, details, recommendation
4. Test thoroughly

---

## 🔐 Security & Privacy

- No data stored or logged
- All analysis happens in real-time
- API keys stored locally in `.env`
- Public blockchain data only

---

## 📝 License

MIT License - see LICENSE file for details

---

## 🙏 Acknowledgments

- **Groq** - AI inference platform
- **Snapshot** - DAO governance data
- **Etherscan** - Smart contract data
- **Streamlit** - Web framework

---

## 📞 Support

- 🐛 Issues: [GitHub Issues](https://github.com/AdityaK-github/Dao-proposal-analyzer/issues)
- 📖 Docs: See `IMPROVEMENTS_LOG.md` for detailed changes
- 💡 Examples: Try the built-in demo contracts and proposals

---

**Built with ❤️ for the DAO community**

**Status**: ✅ Production Ready | **Last Updated**: October 2025
