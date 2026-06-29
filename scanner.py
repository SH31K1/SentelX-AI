import re
import subprocess
import os
 
# Anything outside this set gets replaced when building output filenames.
# Critically includes ':' so IPv6 targets don't produce illegal filenames
# on Windows.
_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]")
 
DEFAULT_TIMEOUT = 600          # 10 minutes — fine for top-1000/top-100 scans
FULL_PORT_SCAN_TIMEOUT = 2400  # 40 minutes — -p- scans need real headroom
 
 
def sanitize_for_filename(target: str) -> str:
    """Turn a target (IPv4, IPv6, or hostname) into a safe filename fragment
    on every OS — notably stripping ':' which is illegal in Windows filenames."""
    return _UNSAFE_FILENAME_CHARS.sub("_", target)
 
 
def build_scan_command(target: str, quick: bool = False) -> list:
    command = ["nmap"]
 
    if quick:
        # Sensible non-interactive default: same flags the pipeline docs
        # describe (-sC -sV), plus --open to cut report noise.
        command.extend(["-sC", "-sV", "--open"])
        command.append(target)
        return command
 
    # Scan type
    print("\n[1] Scan Type:")
    print("  1. -sT  (TCP Connect)")
    print("  2. -sS  (SYN Stealth - requires admin)")
    print("  3. -sA  (ACK scan)")
    print("  4. -sU  (UDP scan)")
    print("  5. -sN  (TCP Null scan)")
    print("  6. -sF  (FIN scan)")
    print("  7. -sX  (Xmas scan)")
    print("  8. Skip (default)")
 
    choice = input("\nChoose [1-8]: ").strip()
    scan_map = {"1": "-sT", "2": "-sS", "3": "-sA", "4": "-sU", "5": "-sN", "6": "-sF", "7": "-sX"}
    if choice in scan_map:
        command.append(scan_map[choice])
    elif choice != "8" and choice != "":
        print(f"  [!] '{choice}' not recognized — skipping scan type flag")
 
    # Port selection
    print("\n[2] Port Range:")
    print("  1. Top 1000 ports (default)")
    print("  2. All ports (-p-)")
    print("  3. Specific ports (e.g. 22,80,443)")
    print("  4. Top 100 ports (--top-ports 100)")
 
    port_choice = input("\nChoose [1-4]: ").strip()
    if port_choice == "2":
        command.append("-p-")
    elif port_choice == "3":
        ports = input("  Enter ports: ").strip()
        if ports:
            command.append(f"-p{ports}")
    elif port_choice == "4":
        # Must be two separate argv tokens — a single string with a space
        # gets passed to nmap as one malformed argument.
        command.extend(["--top-ports", "100"])
 
    # Host discovery
    print("\n[3] Host Discovery:")
 
    if input("  Add --disable-arp-ping? [y/n]: ").strip().lower() == "y":
        command.append("--disable-arp-ping")
 
    if input("  Add -Pn (skip host discovery)? [y/n]: ").strip().lower() == "y":
        command.append("-Pn")
 
    if input("  Add -n (no DNS resolution)? [y/n]: ").strip().lower() == "y":
        command.append("-n")
 
    # Timing
    print("\n[4] Timing:")
    if input("  Set timing template? [y/n]: ").strip().lower() == "y":
        print("  0=paranoid  1=sneaky  2=polite  3=normal  4=aggressive  5=insane")
        t = input("  Enter timing [0-5]: ").strip()
        if t in [str(i) for i in range(6)]:
            command.append(f"-T{t}")
        elif t:
            print(f"  [!] '{t}' is not 0-5 — skipping timing flag")
 
    # Extra options
    print("\n[5] Extra Options:")
 
    if input("  Add -sC (default scripts)? [y/n]: ").strip().lower() == "y":
        command.append("-sC")
 
    if input("  Add -sV (version detection)? [y/n]: ").strip().lower() == "y":
        command.append("-sV")
 
    if input("  Add --reason (show port state reason)? [y/n]: ").strip().lower() == "y":
        command.append("--reason")
 
    if input("  Add -O (OS detection)? [y/n]: ").strip().lower() == "y":
        command.append("-O")
 
    if input("  Add -A (aggressive)? [y/n]: ").strip().lower() == "y":
        command.append("-A")
 
    if input("  Add --open (show only open ports)? [y/n]: ").strip().lower() == "y":
        command.append("--open")
 
    if input("  Add -v (verbose output)? [y/n]: ").strip().lower() == "y":
        command.append("-v")
 
    # Script selection
    print("\n[6] NSE Scripts (optional):")
    print("  1. Skip")
    print("  2. vuln (vulnerability detection)")
    print("  3. auth (authentication checks)")
    print("  4. brute (brute force)")
    print("  5. discovery (extra enumeration)")
    print("  6. Custom (enter your own)")
 
    script_choice = input("\nChoose [1-6]: ").strip()
    script_map = {"2": "vuln", "3": "auth", "4": "brute", "5": "discovery"}
    if script_choice in script_map:
        command.append(f"--script={script_map[script_choice]}")
    elif script_choice == "6":
        custom = input("  Enter script name(s): ").strip()
        if custom:
            command.append(f"--script={custom}")
 
    # Target
    command.append(target)
    return command
 
 
def run_nmap_scan(target: str, output_dir: str = "scans", quick: bool = False, timeout: int = None) -> str:
    if not target:
        return "[!] No target specified"
 
    os.makedirs(output_dir, exist_ok=True)
    safe_target = sanitize_for_filename(target)
    output_file = os.path.join(output_dir, f"{safe_target}.txt")
 
    command = build_scan_command(target, quick=quick)
    command_str = " ".join(command)
 
    # A full port sweep (-p-) routinely takes well past the default 10
    # minutes; give it real headroom unless the caller explicitly set one.
    if timeout is None:
        timeout = FULL_PORT_SCAN_TIMEOUT if "-p-" in command else DEFAULT_TIMEOUT
 
    print(f"\n[*] Running: {command_str}")
    print(f"[*] Scanning {target}... (timeout: {timeout}s)\n")
 
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
 
        if result.returncode != 0:
            print(f"[!] Nmap error: {result.stderr}")
            return result.stderr
 
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Command: {command_str}\n\n")
            f.write(result.stdout)
 
        print(f"[+] Scan complete. Saved to {output_file}")
        return result.stdout
 
    except subprocess.TimeoutExpired:
        return f"[!] Scan timed out after {timeout}s — try a smaller port range or pass a longer timeout"
    except FileNotFoundError:
        return "[!] Nmap not found. Is it installed and in PATH?"
 
 
if __name__ == "__main__":
    target = input("Enter target IP or domain: ").strip()
    output = run_nmap_scan(target)
    print("\n--- SCAN OUTPUT ---")
    print(output)
 
