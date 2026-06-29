import argparse
import hashlib
import json
import os
import re
import sys
import time
 
import chromadb
from sentence_transformers import SentenceTransformer
 
# ──────────────────────────────────────────────────────────────────────────
# CONFIG — resolved from CLI args > environment variables > sane defaults.
# Set TTR_VAULT_PATH / TTR_DB_PATH in your .env (or shell) instead of
# hardcoding paths here, so this file is safe to commit and share.
# ──────────────────────────────────────────────────────────────────────────
DEFAULT_DB_PATH = "./totheroot_db"
COLLECTION_NAME = "cpts_notes"
MANIFEST_FILENAME = "ingest_manifest.json"
 
# Phase mapping based on folder structure
PHASE_MAP = {
    "01-Information Gathering": "enumeration",
    "02-Pre-Exploitation": "pre-exploitation",
    "03-Exploitation": "exploitation",
    "04-Post-Exploitation": "post-exploitation",
    "05-Lateral Movement": "lateral-movement",
    "Documentation and Reporting": "reporting"
}
 
# Skip these - not useful for RAG
SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".docx", ".pdf"}
SKIP_FILENAMES = {"Untitled", "Habits", "Weeks", "Categories", "Project Ideas"}
 
# Service detection keywords. Pure-digit keywords (port numbers) are matched
# with word boundaries so "22" doesn't false-positive inside "2200" etc.
SERVICE_KEYWORDS = {
    "SMB": ["smb", "445", "samba", "cifs"],
    "FTP": ["ftp", "21", "20", "vsftpd"],
    "SSH": ["ssh", "22", "openssh"],
    "HTTP": ["http", "web", "80", "443", "nginx", "apache"],
    "MSSQL": ["mssql", "1433", "sql server"],
    "MySQL": ["mysql", "3306"],
    "RDP": ["rdp", "3389", "remote desktop"],
    "DNS": ["dns", "53", "zone transfer"],
    "SMTP": ["smtp", "25", "587", "mail"],
    "LDAP": ["ldap", "389", "active directory"],
    "WinRM": ["winrm", "5985", "5986", "evil-winrm"],
    "Kerberos": ["kerberos", "88", "kerberoast", "asrep"],
    "NFS": ["nfs", "111", "2049", "showmount"],
    "SNMP": ["snmp", "161", "162"],
    "IPMI": ["ipmi", "623", "bmc", "ilo", "idrac"],
    "LFI": ["lfi", "local file inclusion", "php://filter"],
    "SQLi": ["sql injection", "sqlmap", "union based"],
    "XSS": ["xss", "cross-site scripting"],
    "XXE": ["xxe", "xml external"],
    "ActiveDirectory": ["active directory", "domain controller", "bloodhound", "mimikatz"],
    "PrivEsc": ["privilege escalation", "privesc", "suid", "sudo", "linpeas", "winpeas"],
}
 
 
def _compile_keyword_patterns(keyword_map):
    """Pre-compile word-boundary regexes once instead of re-matching strings
    on every call — cheaper, and avoids false positives like '22' inside '2200'."""
    compiled = {}
    for service, keywords in keyword_map.items():
        compiled[service] = [re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE) for kw in keywords]
    return compiled
 
 
SERVICE_PATTERNS = _compile_keyword_patterns(SERVICE_KEYWORDS)
 
 
def detect_phase(filepath):
    for folder, phase in PHASE_MAP.items():
        if folder in filepath:
            return phase
    return "general"
 
 
def detect_service(filepath, content):
    haystack = f"{filepath}\n{content[:500]}"
    for service, patterns in SERVICE_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(haystack):
                return service
    return "general"
 
 
def chunk_markdown(content, max_chunk=800):
    chunks = []
 
    # Split by headers
    sections = re.split(r'\n(?=#{1,3} )', content)
 
    current_chunk = ""
    for section in sections:
        if not section.strip():
            continue
        if re.match(r'^!\[.*\]\(.*\)$', section.strip()):
            continue
        if len(section.strip()) < 30:
            continue
 
        if len(current_chunk) + len(section) > max_chunk:
            if current_chunk.strip():
                chunks.append(current_chunk.strip())
            current_chunk = section
        else:
            current_chunk += "\n" + section
 
    if current_chunk.strip():
        chunks.append(current_chunk.strip())
 
    return chunks
 
 
def file_hash(content):
    """Content hash used to detect changed notes for incremental ingestion."""
    return hashlib.sha1(content.encode("utf-8", errors="replace")).hexdigest()
 
 
def load_manifest(db_path):
    manifest_path = os.path.join(db_path, MANIFEST_FILENAME)
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[!] Could not read manifest, starting fresh: {e}")
    return {}
 
 
def save_manifest(db_path, manifest):
    os.makedirs(db_path, exist_ok=True)
    manifest_path = os.path.join(db_path, MANIFEST_FILENAME)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
 
 
def parse_args():
    parser = argparse.ArgumentParser(description="Ingest Obsidian vault notes into ChromaDB for RAG")
    parser.add_argument(
        "--vault", "-v",
        default=os.environ.get("TTR_VAULT_PATH"),
        help="Path to your Obsidian vault (or set TTR_VAULT_PATH env var)"
    )
    parser.add_argument(
        "--db", "-d",
        default=os.environ.get("TTR_DB_PATH", DEFAULT_DB_PATH),
        help=f"ChromaDB persistence directory (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--collection", "-c",
        default=COLLECTION_NAME,
        help=f"ChromaDB collection name (default: {COLLECTION_NAME})"
    )
    parser.add_argument(
        "--model", "-m",
        default="all-MiniLM-L6-v2",
        help="SentenceTransformer model to use for embeddings"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Wipe the collection and manifest, re-ingest everything from scratch"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Walk and chunk the vault but skip embedding/writing to the DB"
    )
    args = parser.parse_args()
 
    if not args.vault:
        parser.error("No vault path given. Pass --vault <path> or set TTR_VAULT_PATH.")
    if not os.path.isdir(args.vault):
        parser.error(f"Vault path does not exist or is not a directory: {args.vault}")
 
    return args
 
 
def ingest(args):
    db_path = args.db
    manifest = {} if args.full else load_manifest(db_path)
 
    client = None
    collection = None
    model = None
 
    if not args.dry_run:
        print("[*] Initializing ChromaDB...")
        client = chromadb.PersistentClient(path=db_path)
 
        if args.full:
            try:
                client.delete_collection(args.collection)
                print("[*] Cleared existing collection (--full)")
            except Exception as e:
                print(f"[*] No existing collection to clear ({e})")
            collection = client.create_collection(
                name=args.collection,
                metadata={"hnsw:space": "cosine"}
            )
        else:
            try:
                collection = client.get_collection(args.collection)
            except Exception:
                collection = client.create_collection(
                    name=args.collection,
                    metadata={"hnsw:space": "cosine"}
                )
 
        print("[*] Loading embedding model (first run downloads ~80MB)...")
        model = SentenceTransformer(args.model)
 
    total_chunks = 0
    total_files = 0
    skipped = 0
    unchanged = 0
    seen_paths = set()
 
    print(f"[*] Walking vault: {args.vault}\n")
    start_time = time.time()
 
    for root, dirs, files in os.walk(args.vault):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
 
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SKIP_EXTENSIONS or ext != ".md":
                continue
 
            if any(skip_name.lower() in filename.lower() for skip_name in SKIP_FILENAMES):
                skipped += 1
                continue
 
            filepath = os.path.join(root, filename)
            relative_path = os.path.relpath(filepath, args.vault)
            seen_paths.add(relative_path)
 
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError as e:
                print(f"[!] Could not read {filename}: {e}")
                continue
 
            if len(content.strip()) < 100:
                skipped += 1
                continue
 
            digest = file_hash(content)
            prior = manifest.get(relative_path)
 
            # Incremental skip: unchanged since last ingest
            if not args.full and prior and prior.get("hash") == digest:
                unchanged += 1
                continue
 
            phase = detect_phase(relative_path)
            service = detect_service(relative_path, content)
            chunks = chunk_markdown(content)
 
            if not chunks:
                skipped += 1
                continue
 
            chunk_ids = [f"{relative_path}::chunk_{i}".replace(" ", "_") for i in range(len(chunks))]
 
            if not args.dry_run:
                # Remove this file's previous chunks before re-adding (handles
                # files that shrank, i.e. fewer chunks than the prior version).
                if prior and prior.get("chunk_ids"):
                    try:
                        collection.delete(ids=prior["chunk_ids"])
                    except Exception as e:
                        print(f"[!] Could not clear old chunks for {filename}: {e}")
 
                try:
                    # Batch-encode all chunks for this file in one call —
                    # far faster than encoding chunk-by-chunk.
                    embeddings = model.encode(chunks, batch_size=16).tolist()
                    metadatas = [{
                        "file": filename,
                        "path": relative_path,
                        "phase": phase,
                        "service": service,
                        "chunk_index": i
                    } for i in range(len(chunks))]
 
                    collection.add(
                        ids=chunk_ids,
                        embeddings=embeddings,
                        documents=chunks,
                        metadatas=metadatas
                    )
                except Exception as e:
                    print(f"[!] Error embedding/storing {filename}: {e}")
                    continue
 
            manifest[relative_path] = {"hash": digest, "chunk_ids": chunk_ids}
            total_chunks += len(chunks)
            total_files += 1
            print(f"  [+] {relative_path} -> {len(chunks)} chunks [{phase}] [{service}]")
 
    # Clean up chunks for notes that were deleted/moved out of the vault.
    removed_files = 0
    if not args.full:
        for stale_path in list(manifest.keys()):
            if stale_path not in seen_paths:
                if not args.dry_run and collection is not None:
                    try:
                        collection.delete(ids=manifest[stale_path]["chunk_ids"])
                    except Exception as e:
                        print(f"[!] Could not remove stale chunks for {stale_path}: {e}")
                del manifest[stale_path]
                removed_files += 1
 
    if not args.dry_run:
        save_manifest(db_path, manifest)
 
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"INGESTION COMPLETE{'  (DRY RUN)' if args.dry_run else ''}")
    print(f"  Files processed  : {total_files}")
    print(f"  Files unchanged  : {unchanged}")
    print(f"  Files skipped    : {skipped}")
    print(f"  Files removed    : {removed_files}")
    print(f"  Total new chunks : {total_chunks}")
    print(f"  Time elapsed     : {elapsed:.1f}s")
    print(f"  DB location      : {db_path}")
    print(f"{'='*60}")
 
 
if __name__ == "__main__":
    ingest(parse_args())
 
