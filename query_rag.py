import argparse
import os
import shutil
import subprocess
 
import chromadb
from sentence_transformers import SentenceTransformer
 
DEFAULT_DB_PATH = "./totheroot_db"
COLLECTION_NAME = "cpts_notes"
DEFAULT_MODEL = "qwen3.5:4b"
DEFAULT_OLLAMA_TIMEOUT = 360
 
 
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
 
 
def load_db(db_path: str):
    """Load the ChromaDB collection, with a clear error if ingestion hasn't run yet."""
    client = chromadb.PersistentClient(path=db_path)
    try:
        return client.get_collection(COLLECTION_NAME)
    except Exception:
        raise RuntimeError(
            f"Collection '{COLLECTION_NAME}' not found in '{db_path}'. "
            f"Run ingest_notes.py first to build your knowledge base."
        )
 
 
def search(collection, model, query, phase_filter=None, service_filter=None, n=5):
    embedding = model.encode(query).tolist()
 
    where = {}
    if phase_filter and service_filter:
        where = {"$and": [{"phase": phase_filter}, {"service": service_filter}]}
    elif phase_filter:
        where = {"phase": phase_filter}
    elif service_filter:
        where = {"service": service_filter}
 
    kwargs = {
        "query_embeddings": [embedding],
        "n_results": n,
        "include": ["documents", "metadatas", "distances"]
    }
    if where:
        kwargs["where"] = where
 
    return collection.query(**kwargs)
 
 
def ask_ollama(prompt, model=DEFAULT_MODEL, ollama_exe=None, timeout=DEFAULT_OLLAMA_TIMEOUT):
    try:
        ollama_exe = resolve_ollama_executable(ollama_exe)
    except FileNotFoundError as e:
        return f"[!] {e}"
 
    try:
        print("[*] Waiting for model response (may take 60-90s on first run)...")
        result = subprocess.run(
            [ollama_exe, "run", model],
            input=prompt,
            text=True,
            capture_output=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
 
        if result.returncode != 0:
            return f"[!] Ollama subprocess error: {result.stderr}"
 
        return result.stdout.strip()
 
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s — model may be loading, try again"
    except Exception as e:
        return f"[!] Ollama error: {e}"
 
 
def query_rag(question, db_path, phase=None, service=None, n=5,
              model=DEFAULT_MODEL, ollama_exe=None, timeout=DEFAULT_OLLAMA_TIMEOUT):
    print("\n[*] Loading knowledge base...")
    try:
        collection = load_db(db_path)
    except RuntimeError as e:
        print(f"[!] {e}")
        return
 
    embed_model = SentenceTransformer("all-MiniLM-L6-v2")
 
    print(f"[*] Searching {collection.count()} chunks for: '{question}'")
 
    results = search(collection, embed_model, question, phase, service, n)
 
    if not results["documents"][0]:
        print("[!] No relevant chunks found")
        return
 
    context_parts = []
    print(f"\n[+] Retrieved {len(results['documents'][0])} relevant chunks:")
 
    for i, (doc, meta, dist) in enumerate(zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0]
    )):
        relevance = round((1 - dist) * 100, 1)
        print(f"  [{i+1}] {meta['file']} [{meta['phase']}][{meta['service']}] — {relevance}% match")
        context_parts.append(f"--- From: {meta['file']} ---\n{doc}")
 
    context = "\n\n".join(context_parts)
 
    prompt = f"""You are ToTheRoot, a CPTS-level penetration testing assistant.
Answer ONLY using the context from the user's personal CPTS notes below.
Be specific, technical, and actionable. Include exact commands where present in the notes.
If the notes don't cover the question, say so clearly.
 
=== CONTEXT FROM YOUR CPTS NOTES ===
{context}
 
=== QUESTION ===
{question}
 
=== ANSWER ==="""
 
    print(f"\n[*] Querying Ollama ({model})...")
    response = ask_ollama(prompt, model=model, ollama_exe=ollama_exe, timeout=timeout)
 
    print(f"\n{'='*60}")
    print("TOTHEROOT ANSWER")
    print(f"{'='*60}")
    print(response)
    print(f"{'='*60}\n")
 
 
def parse_args():
    parser = argparse.ArgumentParser(
        description="Query your CPTS notes knowledge base via RAG + local Ollama",
        epilog=(
            "Examples:\n"
            "  python query_rag.py \"how do I exploit SMB null sessions\"\n"
            "  python query_rag.py \"privesc via SUID binaries\" --phase post-exploitation --service PrivEsc\n"
            "  python query_rag.py \"kerberoasting from linux\" --phase lateral-movement --service Kerberos\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("question", help="The question to ask your notes")
    parser.add_argument("--phase", default=None,
                         help="Filter: enumeration, exploitation, post-exploitation, lateral-movement, reporting")
    parser.add_argument("--service", default=None,
                         help="Filter: SMB, FTP, SSH, HTTP, MSSQL, PrivEsc, Kerberos, etc.")
    parser.add_argument("--db", default=os.environ.get("TTR_DB_PATH", DEFAULT_DB_PATH),
                         help=f"ChromaDB persistence directory (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--model", "-m", default=DEFAULT_MODEL, help="Ollama model to use")
    parser.add_argument("-n", "--top", type=int, default=5, help="Number of chunks to retrieve (default: 5)")
    return parser.parse_args()
 
 
def main():
    args = parse_args()
    query_rag(
        args.question,
        db_path=args.db,
        phase=args.phase,
        service=args.service,
        n=args.top,
        model=args.model
    )
 
 
if __name__ == "__main__":
    main()
 
