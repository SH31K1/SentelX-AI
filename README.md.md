# SentelX (ToTheRoot)

Autonomous AI-assisted penetration testing framework.
Built on CPTS methodology. Runs fully offline. No cloud APIs.

SentelX combines network scanning, attack-surface analysis, a local RAG
knowledge base, and a local LLM reasoning layer to automate the
recon-to-exploitation loop — the way a senior analyst thinks through it.

## How it works

```
Target IP/Domain
      |
   scanner.py         Interactive Nmap scan (TCP/UDP, NSE scripts, timing, etc.)
      |
  nmap_parser.py      Parses raw Nmap output into structured JSON
      |
    rules.py          Maps open ports/services to attack vectors
      |
 rag_suggestions.py   Queries local ChromaDB RAG (seeded with your CPTS notes)
      |
     llm.py           Local Ollama model generates analysis and next-step guidance
      |
    cli.py            Orchestrates the full pipeline end to end
```

## What's included

| File | Purpose |
|---|---|
| `cli.py` | Orchestrates the full scan → analysis pipeline |
| `scanner.py` | Interactive Nmap scan helper (TCP/UDP, scripts, timing) |
| `nmap_parser.py` | Parses Nmap text output into structured JSON |
| `rules.py` | Maps common services/ports to attack vectors |
| `rag_suggestions.py` | Pulls relevant CPTS-style guidance from your notes via RAG |
| `query_rag.py` | Ask your local knowledge base questions directly |
| `ingest_notes.py` | Ingests your Obsidian/markdown notes into ChromaDB (incremental) |
| `llm.py` | Local Ollama wrapper for AI analysis output |

## Quick start

### 1. Clone and enter the project
```bash
git clone https://github.com/Parveen-Rawat/ToTheRoot.git
cd ToTheRoot
```

### 2. Create a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Nmap (system package, not pip)
- **Windows:** install from [nmap.org](https://nmap.org), ensure it's on PATH
- **macOS:** `brew install nmap`
- **Linux:** `sudo apt install nmap`

### 5. Install Ollama and pull a model
Install from [ollama.com](https://ollama.com), then:
```bash
ollama pull qwen3.5:4b
```
Make sure the Ollama service is running before using the AI analysis step.

### 6. (Optional) Build your RAG knowledge base
Seed ChromaDB with your own CPTS/pentest notes (Obsidian vault or any folder
of markdown files):
```bash
python ingest_notes.py --vault "/path/to/your/notes" --db ./totheroot_db
```
Reruns are incremental by default — only changed or new notes get re-embedded.
Use `--full` to force a clean rebuild, or `--dry-run` to preview without writing.

### 7. Run a scan
```bash
python cli.py --target <target-ip-or-domain>
```

## Configuration

Most scripts share two environment variables so you only set your paths once:

| Variable | Used by | Default |
|---|---|---|
| `TTR_VAULT_PATH` | `ingest_notes.py` | *(required — your notes folder)* |
| `TTR_DB_PATH` | `ingest_notes.py`, `query_rag.py`, `rag_suggestions.py` | `./totheroot_db` |

Set them once in your shell (or a `.env` file, which is already git-ignored)
instead of passing `--vault`/`--db` on every run.

## Usage reference

**Full pipeline:**
```bash
python cli.py --target 10.10.10.5 [--output scans] [--no-ai] [--model qwen3.5:4b]
```

**Ingest/update your notes:**
```bash
python ingest_notes.py --vault <path> [--db ./totheroot_db] [--full] [--dry-run]
```

**Ask your knowledge base directly:**
```bash
python query_rag.py "how do I exploit SMB null sessions"
python query_rag.py "privesc via SUID binaries" --phase post-exploitation --service PrivEsc
```

## Notes

- This project is intended for **authorized and educational use only**.
- Do not scan targets without explicit, documented permission.
- All AI analysis runs locally via Ollama — no scan data or notes leave your machine.

## Built for

Lab environments, CTF assessments, and CPTS/OSCP preparation.
Only run against targets you have explicit authorization to test.

## Requirements

- Python 3.10+
- Nmap (system install)
- Ollama, with a local model pulled (e.g. `qwen3.5:4b`)
- Python packages in `requirements.txt`: `chromadb`, `sentence-transformers`, `torch`, `numpy`

## License

Released under the MIT License — see [`LICENSE`](LICENSE) for details.

## Author

Parveen Rawat — [Portfolio](https://parveen-rawat.github.io)

---
