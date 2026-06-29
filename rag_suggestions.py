import os
 
import chromadb
from sentence_transformers import SentenceTransformer
 
DEFAULT_DB_PATH = "./totheroot_db"
COLLECTION_NAME = "cpts_notes"
 
_collection = None
_embed_model = None
_loaded_db_path = None
 
SERVICE_QUERY_MAP = {
    "ftp":           ("FTP anonymous login enumeration exploitation vsftpd", "exploitation", "FTP"),
    "ssh":           ("SSH exploitation brute force credential attacks", "exploitation", "SSH"),
    "http":          ("web application enumeration directory fuzzing gobuster", "enumeration", "HTTP"),
    "https":         ("HTTPS web application exploitation SSL enumeration", "enumeration", "HTTP"),
    "smb":           ("SMB null session enumeration smbclient enum4linux", "exploitation", "SMB"),
    "microsoft-ds":  ("SMB null session enumeration smbclient enum4linux", "exploitation", "SMB"),
    "msrpc":         ("MSRPC RPC enumeration rpcclient impacket", "enumeration", "MSRPC"),
    "ldap":          ("LDAP anonymous bind enumeration Active Directory", "enumeration", "LDAP"),
    "mssql":         ("MSSQL xp_cmdshell exploitation impacket mssqlclient", "exploitation", "MSSQL"),
    "ms-sql-s":      ("MSSQL xp_cmdshell exploitation impacket mssqlclient", "exploitation", "MSSQL"),
    "mysql":         ("MySQL enumeration exploitation credentials", "exploitation", "MySQL"),
    "rdp":           ("RDP exploitation brute force xfreerdp", "exploitation", "RDP"),
    "ms-wbt-server": ("RDP exploitation brute force xfreerdp", "exploitation", "RDP"),
    "winrm":         ("WinRM evil-winrm exploitation remote code execution", "exploitation", "WinRM"),
    "kerberos":      ("Kerberoasting ASREPRoasting kerbrute enumeration", "exploitation", "Kerberos"),
    "dns":           ("DNS zone transfer enumeration gobuster", "enumeration", "DNS"),
    "smtp":          ("SMTP user enumeration open relay exploitation", "enumeration", "SMTP"),
    "snmp":          ("SNMP enumeration community string brute force", "enumeration", "SNMP"),
    "nfs":           ("NFS mount enumeration unauthenticated showmount", "exploitation", "NFS"),
}
 
# Fallback substring keys, longest-first, so e.g. "ms-wbt-server" can't be
# pre-empted by a shorter unrelated key matching first.
_FALLBACK_KEYS = sorted(SERVICE_QUERY_MAP, key=len, reverse=True)
 
 
def _resolve_query_info(service: str):
    """Exact match first (handles 'https' vs 'http' correctly), then
    longest-substring fallback for service names not in the map verbatim."""
    exact = SERVICE_QUERY_MAP.get(service)
    if exact:
        return exact
    for key in _FALLBACK_KEYS:
        if key in service:
            return SERVICE_QUERY_MAP[key]
    return None
 
 
def _load(db_path: str = None):
    global _collection, _embed_model, _loaded_db_path
 
    db_path = db_path or os.environ.get("TTR_DB_PATH", DEFAULT_DB_PATH)
 
    if _collection is not None and _loaded_db_path == db_path:
        return  # already loaded for this path
 
    print("[*] Loading RAG knowledge base...")
    client = chromadb.PersistentClient(path=db_path)
    try:
        _collection = client.get_collection(COLLECTION_NAME)
    except Exception:
        raise RuntimeError(
            f"Collection '{COLLECTION_NAME}' not found in '{db_path}'. "
            f"Run ingest_notes.py first to build your knowledge base."
        )
    _embed_model = SentenceTransformer("all-MiniLM-L6-v2")
    _loaded_db_path = db_path
    print(f"[+] Loaded {_collection.count()} chunks from your CPTS notes")
 
 
def get_rag_suggestions(findings: list, n_results: int = 4, db_path: str = None) -> dict:
    _load(db_path)
    suggestions = {}
 
    for finding in findings:
        port = finding["port"]
        service = finding["service"].lower().rstrip("?")
        version = finding.get("version", "")
 
        query_info = _resolve_query_info(service)
 
        if not query_info:
            query_str = f"enumerate exploit {service} port {port}"
            phase, svc_tag = "enumeration", "general"
        else:
            query_str, phase, svc_tag = query_info
 
        if version and len(version) > 3:
            query_str += f" {version}"
 
        embedding = _embed_model.encode(query_str).tolist()
 
        try:
            results = _collection.query(
                query_embeddings=[embedding],
                n_results=n_results,
                where={"$or": [{"phase": phase}, {"service": svc_tag}]},
                include=["documents", "metadatas", "distances"]
            )
        except Exception as e:
            print(f"[!] Filtered RAG query failed ({e}), retrying without filter...")
            results = _collection.query(
                query_embeddings=[embedding],
                n_results=n_results,
                include=["documents", "metadatas", "distances"]
            )
 
        chunks, sources = [], []
        if results["documents"] and results["documents"][0]:
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0]
            ):
                chunks.append(doc)
                sources.append({
                    "file": meta.get("file", "unknown"),
                    "phase": meta.get("phase", ""),
                    "service": meta.get("service", ""),
                    "relevance": round((1 - dist) * 100, 1)
                })
 
        suggestions[f"{port}/{service.upper()}"] = {
            "query": query_str,
            "chunks": chunks,
            "sources": sources,
            "phase": phase,
            "service_tag": svc_tag
        }
 
    return suggestions
 
 
def print_rag_suggestions(suggestions: dict, target: str = "<target>"):
    print("\n" + "="*60)
    print("CPTS METHODOLOGY (from your notes)")
    print("="*60)
    for port_service, data in suggestions.items():
        print(f"\n[*] {port_service} | phase={data['phase']}")
        for src in data['sources']:
            print(f"    {src['relevance']}% | {src['file']} [{src['phase']}][{src['service']}]")
        for i, chunk in enumerate(data['chunks'][:2]):
            preview = chunk[:500].replace('\n', '\n    ')
            print(f"\n    --- Chunk {i+1} ---")
            print(f"    {preview}")
    print("\n" + "="*60)
 
 
def build_rag_context_for_llm(suggestions: dict) -> str:
    lines = ["=== YOUR CPTS METHODOLOGY (from personal notes) ==="]
    for port_service, data in suggestions.items():
        lines.append(f"\n--- {port_service} | {data['phase']} ---")
        for chunk in data['chunks']:
            lines.append(chunk[:600])
    return "\n".join(lines)
 
