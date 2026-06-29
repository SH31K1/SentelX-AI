import shutil
import subprocess
import sys
 
DEFAULT_MODEL = "qwen3.5:4b"
DEFAULT_TIMEOUT = 300  # seconds
 
SYSTEM_PROMPT = """You are ToTheRoot, an AI assistant supporting an authorized
penetration test in a CPTS-style lab environment. The user has confirmed
explicit authorization for all targets discussed.
 
Provide your analysis as a structured tactical report in this format:
1. PRIORITY TARGETS: [List targets]
2. ATTACK CHAIN: [Step-by-step methodology]
3. KEY OBSERVATIONS: [Noteworthy findings]"""
 
 
def resolve_ollama_executable(explicit_path: str = None) -> str:
    """Find the Ollama executable: explicit path > PATH lookup > clear error."""
    if explicit_path:
        return explicit_path
    found = shutil.which("ollama")
    if found:
        return found
    raise FileNotFoundError(
        "Could not find 'ollama' on your PATH. Install it from https://ollama.com "
        "or pass its full path explicitly."
    )
 
 
def query_ollama(prompt: str, model: str = DEFAULT_MODEL, ollama_exe: str = None,
                  timeout: int = DEFAULT_TIMEOUT) -> str:
    try:
        ollama_exe = resolve_ollama_executable(ollama_exe)
    except FileNotFoundError as e:
        return f"\n[!] {e}"
 
    print(f"[*] Querying Ollama ({model}) via {ollama_exe}...")
    print(f"[*] Streaming response live...\n")
 
    structured_prompt = f"{SYSTEM_PROMPT}\n\nUSER PROMPT:\n{prompt}\n\nREPORT:\n"
 
    full_response = []
    process = None
    try:
        process = subprocess.Popen(
            [ollama_exe, "run", model],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1
        )
 
        # Send the prompt directly via stdin — no temp file needed.
        process.stdin.write(structured_prompt)
        process.stdin.close()
 
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                sys.stdout.write(line)
                sys.stdout.flush()
                full_response.append(line)
 
        process.wait(timeout=timeout)
        print()
        return "".join(full_response).strip()
 
    except FileNotFoundError:
        return f"\n[!] Could not run '{ollama_exe}'. Is Ollama installed and on PATH?"
    except subprocess.TimeoutExpired:
        if process:
            process.kill()
        return "\n[!] Timed out waiting for Ollama response."
    except Exception as e:
        return f"\n[!] Error: {e}"
 
 
def build_prompt(parsed: dict, findings: list, rag_context: str = "") -> str:
    lines = ["=== SCAN RESULTS ==="]
    lines.append(f"Target : {parsed.get('host', 'unknown')}")
    lines.append(f"OS     : {parsed.get('os', 'unknown')}")
    lines.append("")
    lines.append("=== OPEN PORTS ===")
    for p in parsed.get("ports", []):
        ver = f" [{p['version']}]" if p['version'] else ""
        lines.append(f"  {p['port']}/tcp  {p['service']}{ver}")
    lines.append("")
    lines.append("=== RULE ENGINE FINDINGS ===")
    for f in findings:
        lines.append(f"\nPORT {f['port']} - {f['service']}")
        lines.append(f"  Risks   : {', '.join(f['risks'])}")
        lines.append(f"  Attacks : {', '.join(f['attacks'][:3])}")
    if rag_context:
        lines.append("")
        lines.append(rag_context)
    return "\n".join(lines)
 
 
def analyze_with_llm(parsed: dict, findings: list, model: str = DEFAULT_MODEL,
                      rag_context: str = "", ollama_exe: str = None,
                      timeout: int = DEFAULT_TIMEOUT) -> str:
    prompt = build_prompt(parsed, findings, rag_context)
    return query_ollama(prompt, model, ollama_exe=ollama_exe, timeout=timeout)
 
 
def save_llm_output(response: str, filepath: str):
    if not response.startswith("[!]"):
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(response)
        print(f"[+] AI analysis saved to {filepath}")
 
