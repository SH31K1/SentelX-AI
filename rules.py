import json
import os
 
# Rule database - service/port mapped to attack paths
RULES = {
    "ports": {
        21: {
            "name": "FTP",
            "risks": ["Anonymous login", "Brute force", "FTP bounce attack"],
            "attacks": [
                "Check anonymous login: ftp <target> (user: anonymous)",
                "Enumerate: nmap --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor -p 21 <target>",
                "Brute force: hydra -L users.txt -P pass.txt ftp://<target>",
                "Check version exploits: searchsploit vsftpd"
            ]
        },
        22: {
            "name": "SSH",
            "risks": ["Brute force", "Weak credentials", "Old version exploits"],
            "attacks": [
                "Enumerate: nmap --script ssh-auth-methods -p 22 <target>",
                "Brute force: hydra -L users.txt -P pass.txt ssh://<target>",
                "Check version: searchsploit openssh <version>",
                "Try default creds: root:root, admin:admin, root:toor"
            ]
        },
        23: {
            "name": "Telnet",
            "risks": ["Cleartext credentials", "Brute force", "Unauthenticated access"],
            "attacks": [
                "Connect: telnet <target>",
                "Brute force: hydra -L users.txt -P pass.txt telnet://<target>",
                "Enumerate: nmap --script telnet-ntlm-info -p 23 <target>"
            ]
        },
        25: {
            "name": "SMTP",
            "risks": ["User enumeration", "Open relay", "Email spoofing"],
            "attacks": [
                "Enumerate users: smtp-user-enum -M VRFY -U users.txt -t <target>",
                "Check open relay: nmap --script smtp-open-relay -p 25 <target>",
                "Enumerate: nmap --script smtp-commands,smtp-enum-users -p 25 <target>"
            ]
        },
        53: {
            "name": "DNS",
            "risks": ["Zone transfer", "DNS enumeration", "Cache poisoning"],
            "attacks": [
                "Zone transfer: dig axfr @<target> <domain>",
                "Enumerate subdomains: gobuster dns -d <domain> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
                "Brute force DNS: fierce --domain <domain>",
                "Enumerate: nmap --script dns-zone-transfer -p 53 <target>"
            ]
        },
        80: {
            "name": "HTTP",
            "risks": ["Web vulnerabilities", "Directory traversal", "LFI/RFI", "SQLi", "XSS"],
            "attacks": [
                "Directory enum: gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt",
                "Vulnerability scan: nikto -h http://<target>",
                "SQL injection: sqlmap -u 'http://<target>/page?id=1' --batch --dbs",
                "Check technologies: whatweb http://<target>",
                "Enumerate: nmap --script http-enum,http-title -p 80 <target>"
            ]
        },
        88: {
            "name": "Kerberos",
            "risks": ["AS-REP Roasting", "Kerberoasting", "Pass-the-Ticket"],
            "attacks": [
                "AS-REP Roast: impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass",
                "Kerberoast: impacket-GetUserSPNs <domain>/<user>:<pass> -request",
                "Enumerate users: kerbrute userenum -d <domain> --dc <target> users.txt",
                "Brute force: kerbrute bruteuser -d <domain> --dc <target> -P pass.txt <user>"
            ]
        },
        110: {
            "name": "POP3",
            "risks": ["Cleartext credentials", "Brute force"],
            "attacks": [
                "Connect: nc <target> 110",
                "Brute force: hydra -L users.txt -P pass.txt pop3://<target>",
                "Enumerate: nmap --script pop3-capabilities -p 110 <target>"
            ]
        },
        135: {
            "name": "MSRPC",
            "risks": ["RPC enumeration", "DCOM exploitation", "Lateral movement"],
            "attacks": [
                "Enumerate RPC: rpcclient -U '' <target>",
                "Dump RPC endpoints: impacket-rpcdump <target>",
                "Enumerate: nmap --script msrpc-enum -p 135 <target>",
                "Check DCOM: impacket-dcomexec <domain>/<user>:<pass>@<target>"
            ]
        },
        139: {
            "name": "NetBIOS",
            "risks": ["NetBIOS enumeration", "NULL sessions"],
            "attacks": [
                "Enumerate: nbtscan <target>",
                "NULL session: rpcclient -U '' -N <target>",
                "Enumerate shares: smbclient -L //<target> -N",
                "Enumerate: nmap --script nbstat.nse -p 139 <target>"
            ]
        },
        143: {
            "name": "IMAP",
            "risks": ["Cleartext credentials", "Brute force"],
            "attacks": [
                "Connect: nc <target> 143",
                "Brute force: hydra -L users.txt -P pass.txt imap://<target>",
                "Enumerate: nmap --script imap-capabilities -p 143 <target>"
            ]
        },
        389: {
            "name": "LDAP",
            "risks": ["Anonymous bind", "LDAP enumeration", "Credential harvesting"],
            "attacks": [
                "Anonymous bind: ldapsearch -x -H ldap://<target> -b 'dc=<domain>,dc=com'",
                "Enumerate users: ldapsearch -x -H ldap://<target> -b 'dc=domain,dc=com' '(objectClass=user)'",
                "Enumerate: nmap --script ldap-search -p 389 <target>",
                "Bloodhound collection: bloodhound-python -d <domain> -u <user> -p <pass> -ns <target>"
            ]
        },
        443: {
            "name": "HTTPS",
            "risks": ["Web vulnerabilities", "SSL/TLS issues", "Certificate info"],
            "attacks": [
                "Directory enum: gobuster dir -u https://<target> -w /usr/share/wordlists/dirb/common.txt -k",
                "SSL scan: sslscan <target>",
                "Vulnerability scan: nikto -h https://<target> -ssl",
                "Check cert: openssl s_client -connect <target>:443"
            ]
        },
        445: {
            "name": "SMB",
            "risks": ["Null sessions", "EternalBlue", "Share enumeration", "Relay attacks", "Brute force"],
            "attacks": [
                "Enumerate shares: smbclient -L //<target> -N",
                "Check null session: smbmap -H <target>",
                "Enumerate: enum4linux -a <target>",
                "Check vulnerabilities: nmap --script smb-vuln* -p 445 <target>",
                "Brute force: crackmapexec smb <target> -u users.txt -p pass.txt",
                "Check EternalBlue: nmap --script smb-vuln-ms17-010 -p 445 <target>",
                "Relay attack: responder -I <interface> -rdw"
            ]
        },
        1433: {
            "name": "MSSQL",
            "risks": ["Weak credentials", "xp_cmdshell", "SQL injection"],
            "attacks": [
                "Enumerate: nmap --script ms-sql-info,ms-sql-empty-password -p 1433 <target>",
                "Brute force: hydra -L users.txt -P pass.txt mssql://<target>",
                "Login: impacket-mssqlclient <domain>/<user>:<pass>@<target>",
                "Enable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
            ]
        },
        1521: {
            "name": "Oracle DB",
            "risks": ["Weak credentials", "SID enumeration"],
            "attacks": [
                "SID enum: odat sidguesser -s <target>",
                "Brute force: hydra -L users.txt -P pass.txt oracle://<target>",
                "Enumerate: nmap --script oracle-sid-brute -p 1521 <target>"
            ]
        },
        2049: {
            "name": "NFS",
            "risks": ["Unauthenticated mount", "File read/write"],
            "attacks": [
                "Show mounts: showmount -e <target>",
                "Mount share: mount -t nfs <target>:/ /mnt/nfs",
                "Enumerate: nmap --script nfs-ls,nfs-showmount -p 2049 <target>"
            ]
        },
        3306: {
            "name": "MySQL",
            "risks": ["Weak credentials", "File read", "UDF exploitation"],
            "attacks": [
                "Login: mysql -h <target> -u root -p",
                "Brute force: hydra -L users.txt -P pass.txt mysql://<target>",
                "Enumerate: nmap --script mysql-info,mysql-empty-password -p 3306 <target>",
                "Read files: SELECT LOAD_FILE('/etc/passwd');"
            ]
        },
        3389: {
            "name": "RDP",
            "risks": ["Brute force", "BlueKeep", "Credential stuffing"],
            "attacks": [
                "Check BlueKeep: nmap --script rdp-vuln-ms12-020 -p 3389 <target>",
                "Brute force: hydra -L users.txt -P pass.txt rdp://<target>",
                "Connect: xfreerdp /u:<user> /p:<pass> /v:<target>",
                "Enumerate: nmap --script rdp-enum-encryption -p 3389 <target>"
            ]
        },
        5985: {
            "name": "WinRM",
            "risks": ["Remote code execution", "Credential attacks"],
            "attacks": [
                "Connect: evil-winrm -i <target> -u <user> -p <pass>",
                "Brute force: crackmapexec winrm <target> -u users.txt -p pass.txt",
                "Check access: crackmapexec winrm <target> -u <user> -p <pass>"
            ]
        },
        6379: {
            "name": "Redis",
            "risks": ["Unauthenticated access", "RCE via config write"],
            "attacks": [
                "Connect: redis-cli -h <target>",
                "Check auth: redis-cli -h <target> ping",
                "Enumerate: nmap --script redis-info -p 6379 <target>",
                "RCE via SSH key: config set dir /root/.ssh"
            ]
        },
        8080: {
            "name": "HTTP-Alt",
            "risks": ["Web vulnerabilities", "Admin panels", "Default credentials"],
            "attacks": [
                "Directory enum: gobuster dir -u http://<target>:8080 -w /usr/share/wordlists/dirb/common.txt",
                "Vulnerability scan: nikto -h http://<target>:8080",
                "Check admin panels: /manager, /admin, /console",
                "SQL injection: sqlmap -u 'http://<target>:8080/page?id=1' --batch"
            ]
        }
    },
    "services": {
        "http": 80,
        "http-proxy": 8080,
        "https": 443,
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "dns": 53,
        "domain": 53,            # nmap commonly labels DNS as "domain"
        "pop3": 110,
        "imap": 143,
        "smb": 445,
        "microsoft-ds": 445,
        "msrpc": 135,
        "netbios-ssn": 139,
        "ldap": 389,
        "kerberos": 88,
        "rdp": 3389,
        "ms-wbt-server": 3389,
        "mysql": 3306,
        "ms-sql-s": 1433,
        "oracle-tns": 1521,
        "nfs": 2049,
        "redis": 6379,
        "winrm": 5985
    }
}
 
# States worth surfacing findings for. "open|filtered" is nmap's standard
# ambiguous result for UDP scans (it can't tell open from filtered) — still
# worth flagging rather than discarding, since the parser now reports it.
ACTIONABLE_STATES = {"open", "open|filtered"}
 
 
def analyze(parsed: dict) -> list:
    findings = []
    target = parsed.get("host", "<target>")
 
    for port_info in parsed.get("ports", []):
        port = port_info["port"]
        service = port_info["service"].lower()
        version = port_info["version"]
        state = port_info["state"]
        protocol = port_info.get("protocol", "tcp")
 
        if state not in ACTIONABLE_STATES:
            continue
 
        rule = None
 
        # Match by port number first
        if port in RULES["ports"]:
            rule = RULES["ports"][port]
 
        # Match by service name if no port match
        elif service in RULES["services"]:
            mapped_port = RULES["services"][service]
            if mapped_port in RULES["ports"]:
                rule = RULES["ports"][mapped_port]
 
        if rule:
            # Replace <target> placeholder with actual target
            attacks = [a.replace("<target>", target) for a in rule["attacks"]]
 
            findings.append({
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": rule["name"],
                "version": version,
                "risks": rule["risks"],
                "attacks": attacks
            })
        else:
            # Unknown service - flag for manual review
            findings.append({
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
                "risks": ["Unknown service - manual review required"],
                "attacks": [
                    f"Banner grab: nc -nv {target} {port}",
                    f"Enumerate: nmap -sV --script=banner -p {port} {target}",
                    f"Search exploits: searchsploit {service}"
                ]
            })
 
    return findings
 
 
def print_findings(findings: list):
    if not findings:
        print("[!] No findings to display")
        return
 
    print("\n" + "="*60)
    print("RULE ENGINE - ATTACK SURFACE ANALYSIS")
    print("="*60)
 
    for f in findings:
        flag = f" [{f['state']}]" if f.get("state") != "open" else ""
        print(f"\n[!] PORT {f['port']}/{f.get('protocol', 'tcp')} - {f['service'].upper()}{flag}")
        if f['version']:
            print(f"    Version  : {f['version']}")
        print(f"    Risks    : {', '.join(f['risks'])}")
        print(f"    Attacks  :")
        for attack in f['attacks']:
            print(f"      - {attack}")
 
    print("\n" + "="*60)
 
 
if __name__ == "__main__":
    scans_dir = "scans"
    if not os.path.isdir(scans_dir):
        print(f"[!] No '{scans_dir}/' folder found. Run cli.py or nmap_parser.py first.")
        exit()
 
    files = [f for f in os.listdir(scans_dir) if f.endswith(".json")]
 
    if not files:
        print("[!] No parsed JSON files found. Run nmap_parser.py first.")
        exit()
 
    print("\nAvailable parsed scans:")
    for i, f in enumerate(files):
        print(f"  {i+1}. {f}")
 
    choice = input("\nChoose scan to analyze [number]: ").strip()
    try:
        selected = files[int(choice) - 1]
    except (ValueError, IndexError):
        print("[!] Invalid choice")
        exit()
 
    filepath = os.path.join(scans_dir, selected)
 
    with open(filepath, "r", encoding="utf-8") as f:
        parsed = json.load(f)
 
    findings = analyze(parsed)
    print_findings(findings)
 
