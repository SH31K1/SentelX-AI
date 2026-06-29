import re
import json
 
# Reasons nmap can print after the service name when --reason is used,
# optionally followed by "ttl <n>". Both need stripping to recover the
# real version string.
REASON_PREFIX = re.compile(
    r"^(syn-ack|reset|no-response|host-unreach|echo-reply|admin-prohibited)"
    r"(\s+ttl\s+\d+)?\s*",
    re.IGNORECASE
)
 
# Ordered fallbacks for OS detection — nmap reports OS info differently
# depending on whether -O found a confident match, a fuzzy guess, or
# nothing at all (in which case Service Info is the only hint available).
OS_PATTERNS = [
    re.compile(r"OS details:\s*(.+)"),
    re.compile(r"Aggressive OS guesses:\s*(.+)"),
    re.compile(r"Running:\s*(.+)"),
    re.compile(r"Service Info:.*?OS:\s*([^;,\n]+)"),
]
 
PORT_LINE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open\|filtered|closed\|filtered|open|closed|filtered)\s+(\S+)\s*(.*)"
)
 
HOST_LINE = re.compile(r"Nmap scan report for (.+)")
HOST_WITH_IP = re.compile(r"^(.*?)\s+\(([\d.:a-fA-F]+)\)$")  # "name (ip)" form
 
 
def parse_nmap_output(raw_output: str) -> dict:
    result = {
        "host": "",
        "ip": "",
        "os": "",
        "ports": []
    }
 
    # Extract host — nmap prints either "name (ip)" or just "ip"/"name".
    host_match = HOST_LINE.search(raw_output)
    if host_match:
        raw_host = host_match.group(1).strip()
        split = HOST_WITH_IP.match(raw_host)
        if split:
            result["host"] = split.group(1).strip()
            result["ip"] = split.group(2).strip()
        else:
            result["host"] = raw_host
            result["ip"] = raw_host  # it's already just an IP
 
    # Extract OS — try each pattern in order of reliability.
    for pattern in OS_PATTERNS:
        os_match = pattern.search(raw_output)
        if os_match:
            result["os"] = os_match.group(1).strip()
            break
 
    # Extract ports - only grab the port line itself, not script output.
    for line in raw_output.splitlines():
        match = PORT_LINE.match(line)
        if not match:
            continue
 
        version = REASON_PREFIX.sub("", match.group(5).strip())
 
        # Ignore version if it starts with script output characters
        if version.startswith("|") or version.startswith("_"):
            version = ""
 
        port_entry = {
            "port": int(match.group(1)),
            "protocol": match.group(2),
            "state": match.group(3).strip(),
            "service": match.group(4).strip().rstrip("?"),
            "version": version
        }
        result["ports"].append(port_entry)
 
    return result
 
 
def parse_from_file(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    return parse_nmap_output(raw)
 
 
def save_parsed(parsed: dict, filepath: str):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=4)
    print(f"[+] Parsed output saved to {filepath}")
 
 
if __name__ == "__main__":
    import os
 
    scans_dir = "scans"
    if not os.path.isdir(scans_dir):
        print(f"[!] No '{scans_dir}/' folder found")
        exit()
 
    files = [f for f in os.listdir(scans_dir) if f.endswith(".txt")]
 
    if not files:
        print("[!] No scan files found in scans/ folder")
        exit()
 
    print("\nAvailable scans:")
    for i, f in enumerate(files):
        print(f"  {i+1}. {f}")
 
    choice = input("\nChoose scan to parse [number]: ").strip()
    try:
        selected = files[int(choice) - 1]
    except (ValueError, IndexError):
        print("[!] Invalid choice")
        exit()
 
    filepath = os.path.join(scans_dir, selected)
    parsed = parse_from_file(filepath)
 
    json_file = filepath.replace(".txt", ".json")
    save_parsed(parsed, json_file)
 
    print("\n--- PARSED OUTPUT ---")
    print(json.dumps(parsed, indent=4))
