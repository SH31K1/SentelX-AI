Readme · MDSentelX (AI SD)


Autonomous AI-Assisted Penetration Testing Framework

AI-powered penetration testing framework that combines Nmap, rule-based attack analysis, Retrieval-Augmented Generation (RAG), and local Large Language Models (LLMs) to assist authorized security assessments entirely offline.



SentelX combines network scanning, attack-surface analysis, a local RAG
knowledge base, and a local LLM reasoning layer to automate the
recon-to-exploitation loop — the way a senior analyst thinks through it.


Features


🤖 AI-assisted penetration testing workflow
🌐 Interactive Nmap scanning (TCP, UDP, NSE scripts, timing)
🛡️ Rule-based attack surface analysis
📚 Local RAG knowledge base using ChromaDB
🧠 Local LLM integration through Ollama
📄 Automatic Markdown report generation
🔒 Fully offline architecture (no cloud APIs)
🎯 CPTS-inspired methodology
⚡ Modular and extensible Python architecture



Architecture

                  Target IP / Domain
                          │
                    scanner.py        Interactive Nmap scan
                          │
                 nmap_parser.py       Parses output into structured JSON
                          │
                     rules.py         Maps ports/services to attack vectors
                          │
                rag_suggestions.py    Queries local ChromaDB RAG
                          │
                      llm.py          Local Ollama model reasoning
                          │
                      cli.py          Orchestrates the full pipeline
                          │
            Markdown Report + AI Analysis


Project Structure

FileDescriptioncli.pyMain entry point that orchestrates the complete penetration testing workflowscanner.pyInteractive Nmap scanner supporting TCP, UDP, and NSE scriptsnmap_parser.pyConverts raw Nmap output into structured JSONrules.pyMaps discovered services to attack techniquesrag_suggestions.pyRetrieves CPTS guidance from your local RAG databasequery_rag.pyQuery your knowledge base directlyingest_notes.pyIngest markdown notes into ChromaDB (incremental)llm.pyLocal Ollama integration for AI reasoning


Quick Start

1. Clone the repository

bashgit clone https://github.com/SH31K1/SentelX-AI
cd SentelX-AI

2. Create a virtual environment

Windows (PowerShell):

powershellpython -m venv .venv
.venv\Scripts\Activate.ps1

Linux / macOS:

bashpython3 -m venv .venv
source .venv/bin/activate

3. Install dependencies

bashpip install -r requirements.txt

4. Install Nmap (system package, not pip)


Windows: download from nmap.org, ensure it's on PATH
Linux: sudo apt install nmap
macOS: brew install nmap


5. Install Ollama and pull a model

Install from ollama.com, then:

bashollama pull qwen3.5:4b

Make sure the Ollama service is running before using the AI analysis step.

7. Run SentelX

bashpython cli.py --target 10.10.10.5

or

bashpython cli.py --target example.com



Usage

Full scan:

bashpython cli.py --target 10.10.10.5

Scan without AI analysis:

bashpython cli.py --target 10.10.10.5 --no-ai

Use a different Ollama model:

bashpython cli.py --target 10.10.10.5 --model qwen3.5:4b

Update your knowledge base:

bashpython ingest_notes.py --vault <path> [--db ./totheroot_db] [--full] [--dry-run]

Ask the RAG directly:

bashpython query_rag.py "how do I exploit SMB null sessions"
python query_rag.py "privesc via SUID binaries" --phase post-exploitation --service PrivEsc


Requirements


Python 3.10+
Nmap (system install)
Ollama, with a local model pulled (e.g. qwen3.5:4b)
Python packages in requirements.txt: chromadb, sentence-transformers, torch, numpy



Security Notice

⚠️ SentelX is intended only for:


Authorized penetration testing
Capture The Flag (CTF) competitions
CPTS / OSCP practice labs
Security research


All AI analysis runs locally via Ollama — no scan data or notes leave your machine.

Never scan or attack systems without explicit, documented authorization.


Roadmap


Multi-target scanning
Autonomous attack planning
Web vulnerability modules
Active Directory support
Docker deployment
Web dashboard
Plugin ecosystem



License

This project is released under the MIT License — see LICENSE for details.


Author

Sheik Dawood


GitHub: https://github.com/SH31K1
Project: SentelX (AI SD)


