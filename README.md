# 🛡️ SentelX (AI SD)

> **Autonomous AI-Assisted Penetration Testing Framework**
>
> An offline AI-powered penetration testing framework that combines **Nmap**, **Rule-Based Analysis**, **Retrieval-Augmented Generation (RAG)**, and **Local Large Language Models (LLMs)** to assist authorized security assessments.

---

<p align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-success)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Offline](https://img.shields.io/badge/AI-100%25%20Offline-red)
![Status](https://img.shields.io/badge/Status-Active-orange)

</p>

---

## 🚀 What is SentelX?

SentelX is an autonomous AI-assisted penetration testing framework designed to help security professionals perform **authorized penetration tests** entirely offline.

Unlike traditional scanners, SentelX doesn't simply list open ports—it correlates discovered services with attack vectors, retrieves relevant CPTS knowledge from a local RAG database, and uses a local LLM to generate expert-level security analysis.

Everything runs locally.

No cloud.

No API keys.

No data leaves your machine.

---

# ✨ Features

* 🤖 AI-Assisted Penetration Testing
* 🌐 Interactive Nmap Scanner
* 🛡 Rule-Based Attack Surface Analysis
* 📚 Local RAG Knowledge Base (ChromaDB)
* 🧠 Local LLM Integration (Ollama)
* 📄 Automatic Markdown Report Generation
* 🔒 100% Offline Architecture
* 🎯 CPTS-Inspired Methodology
* ⚡ Modular Python Architecture
* 📈 Easy to Extend

---

# 🏗 Architecture

```text
               Target IP / Domain
                       │
                 scanner.py
          Interactive Nmap Scan
                       │
              nmap_parser.py
      Parse XML → Structured JSON
                       │
                 rules.py
      Attack Surface Analysis
                       │
          rag_suggestions.py
        Local ChromaDB Search
                       │
                  llm.py
      Local Ollama AI Reasoning
                       │
                  cli.py
        Complete Scan Pipeline
                       │
       Markdown Report + AI Analysis
```

---

# 📂 Project Structure

```text
SentelX-AI/
│
├── cli.py
├── scanner.py
├── nmap_parser.py
├── rules.py
├── rag_suggestions.py
├── ingest_notes.py
├── query_rag.py
├── llm.py
├── requirements.txt
├── README.md
└── LICENSE
```

---

# ⚙️ Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/SH31K1/SentelX-AI.git
cd SentelX-AI
```

---

## 2️⃣ Create Virtual Environment

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3️⃣ Install Python Packages

```bash
pip install -r requirements.txt
```

---

## 4️⃣ Install Nmap

Windows

Download from:

https://nmap.org/download.html

Linux

```bash
sudo apt install nmap
```

macOS

```bash
brew install nmap
```

---

## 5️⃣ Install Ollama

Install Ollama and pull a local model.

```bash
ollama pull qwen3.5:4b
```

---

# 🚀 Usage

## Full Scan

```bash
python cli.py --target 10.10.10.5
```

---

## Scan Without AI

```bash
python cli.py --target 10.10.10.5 --no-ai
```

---

## Use Different Model

```bash
python cli.py --target example.com --model qwen3.5:4b
```

---

## Update RAG Database

```bash
python ingest_notes.py --vault <path>
```

---

## Query Knowledge Base

```bash
python query_rag.py "how do I exploit SMB null sessions"
```

---

# 📄 Sample Workflow

```text
Target
   │
   ▼
Nmap Scan
   │
   ▼
Port Detection
   │
   ▼
Rule Analysis
   │
   ▼
Local RAG Search
   │
   ▼
Local AI Reasoning
   │
   ▼
Markdown Report
```

---

# 📦 Requirements

* Python 3.10+
* Nmap
* Ollama
* qwen3.5:4b
* ChromaDB
* Sentence Transformers
* Torch
* NumPy

---

# 🔒 Security Notice

SentelX is intended only for:

* Authorized Penetration Testing
* Capture The Flag (CTF)
* CPTS Labs
* OSCP Practice
* Security Research

Never scan systems without explicit authorization.

---

# 🛣 Roadmap

* Multi-target Scanning
* Autonomous Attack Planning
* Web Vulnerability Modules
* Active Directory Enumeration
* Docker Deployment
* Web Dashboard
* Plugin System
* AI Memory
* AI Agent Mode

---

# 🤝 Contributing

Contributions, feature requests, and bug reports are welcome.

If you have ideas to improve SentelX, feel free to open an Issue or submit a Pull Request.

---

# 📜 License

MIT License

---

# 👨‍💻 Author

**Sheik Dawood**

Cybersecurity Student • Offensive Security Enthusiast

⭐ If you found this project useful, consider giving it a **Star** and following the repository for future updates.
