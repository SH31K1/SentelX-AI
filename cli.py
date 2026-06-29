import argparse
import json
import os
import sys
import shutil
 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
 
from scanner import run_nmap_scan
from nmap_parser import parse_nmap_output, save_parsed
from rules import analyze, print_findings
from llm import analyze_with_llm, save_llm_output
 
AUTHOR = "Sheik Dawood"
VERSION = "v1.0"
 
BANNER = f"""
███████╗███████╗███╗   ██╗████████╗ █████╗ ██╗     ██╗  ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██║     ╚██╗██╔╝
███████╗█████╗  ██╔██╗ ██║   ██║   ███████║██║      ╚███╔╝
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██║      ██╔██╗
███████║███████╗██║ ╚████║   ██║   ██║  ██║███████╗██╔╝ ██╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
         AI Penetration Testing | RAG + Local LLM | Zero Cloud | CPTS-Driven
                     Built by {AUTHOR}  |  {VERSION}
"""
 
def print_banner(text):
    """Draws a dynamic, full-width terminal banner"""
    width = shutil.get_terminal_size().columns
    print("\n" + "━" * width)
    print(f" {text} ".center(width, "█"))
    print("━" * width + "\n")
 
 
def save_markdown_report(target, parsed, findings, rag_suggestions, output_dir, ai_response=None):
    md_file = os.path.join(output_dir, f"{target.replace('.', '_')}_report.md")
    lines = []
    lines.append("# ToTheRoot — Penetration Test Report\n")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Target | `{parsed['host']}` |")
    lines.append(f"| OS | {parsed['os'] or 'Unknown'} |")
    lines.append(f"| Open Ports | {len(parsed['ports'])} |\n")
 
    lines.append("## Open Ports\n")
    lines.append("| Port | Service | Version |")
    lines.append("|------|---------|---------|")
    for p in parsed["ports"]:
        lines.append(f"| {p['port']}/tcp | {p['service']} | {p['version'] or '-'} |")
    lines.append("")
 
    lines.append("## Attack Surface (Rule Engine)\n")
    for f in findings:
        lines.append(f"### PORT {f['port']} — {f['service'].upper()}")
        lines.append(f"**Risks:** {', '.join(f['risks'])}\n")
        for attack in f["attacks"]:
            lines.append(f"```\n{attack}\n```")
        lines.append("")
 
    if rag_suggestions:
        lines.append("## CPTS Methodology (Your Notes)\n")
        for port_service, data in rag_suggestions.items():
            lines.append(f"### {port_service}")
            lines.append(f"*Phase: {data['phase']} | Sources: {len(data['sources'])}*\n")
            for src in data['sources']:
                lines.append(f"- {src['relevance']}% — {src['file']}")
            lines.append("")
            for i, chunk in enumerate(data['chunks'][:2]):
                lines.append(f"```\n{chunk[:600]}\n```")
            lines.append("")
 
    if ai_response:
        lines.append("## AI Analysis\n")
        lines.append(ai_response)
        lines.append("")
 
    with open(md_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] Report saved: {md_file}")
 
 
def run_pipeline(target: str, output_dir: str = "scans", skip_llm: bool = False, model: str = "qwen3.5:4b"):
    print(BANNER)
    print(f"[*] Target : {target}")
    print(f"[*] Model  : {model}")
    print(f"[*] AI     : {'disabled' if skip_llm else 'enabled'}")
    print("-" * 60)
 
    os.makedirs(output_dir, exist_ok=True)
    safe_target = target.replace('.', '_')
 
    # STEP 1: SCAN
    print_banner("STEP 1/5: RECONNAISSANCE")
    raw_output = run_nmap_scan(target, output_dir)
    if raw_output.startswith("[!]"):
        print(raw_output)
        return
 
    # STEP 2: PARSE
    print_banner("STEP 2/5: PARSING & OS DETECTION")
    parsed = parse_nmap_output(raw_output)
    json_file = os.path.join(output_dir, f"{safe_target}.json")
    save_parsed(parsed, json_file)
    print(f"  Host : {parsed['host']}")
    print(f"  OS   : {parsed['os'] or 'unknown'}")
    print(f"  Ports: {len(parsed['ports'])} open")
 
    # STEP 3: RULES
    print_banner("STEP 3/5: ATTACK SURFACE MAPPING")
    findings = analyze(parsed)
    print_findings(findings)
 
    # STEP 4: RAG
    print_banner("STEP 4/5: QUERYING CPTS KNOWLEDGE BASE")
    rag_suggestions = None
    rag_context = ""
    try:
        from rag_suggestions import get_rag_suggestions, print_rag_suggestions, build_rag_context_for_llm
        rag_suggestions = get_rag_suggestions(findings)
        print_rag_suggestions(rag_suggestions, target)
        rag_context = build_rag_context_for_llm(rag_suggestions)
        total = sum(len(s['sources']) for s in rag_suggestions.values())
        print(f"[+] RAG retrieved {total} chunks from your notes")
    except Exception as e:
        print(f"[!] RAG unavailable: {e} — continuing without it")
 
    # STEP 5: LLM
    ai_response = None
    if not skip_llm:
        confirm = input("\n[?] Send to Ollama for AI analysis? [y/n]: ").strip().lower()
        if confirm == "y":
            print_banner("STEP 5/5: AUTONOMOUS AI ANALYSIS")
            ai_response = analyze_with_llm(parsed, findings, model, rag_context)
            print("\n" + "="*60)
            print("AI ANALYSIS — ToTheRoot")
            print("="*60)
            print(ai_response)
            print("="*60)
            ai_file = os.path.join(output_dir, f"{safe_target}_ai_analysis.txt")
            save_llm_output(ai_response, ai_file)
        else:
            print("[*] AI skipped.")
    else:
        print("\n[5/5] AI skipped (--no-ai)")
 
    # SAVE REPORT
    save_markdown_report(target, parsed, findings, rag_suggestions, output_dir, ai_response)
 
    print("\n" + "="*60)
    print("COMPLETE — OUTPUT FILES")
    print("="*60)
    print(f"  Raw scan : {output_dir}/{safe_target}.txt")
    print(f"  Parsed   : {output_dir}/{safe_target}.json")
    print(f"  Report   : {output_dir}/{safe_target}_report.md")
    if ai_response:
        print(f"  AI report: {output_dir}/{safe_target}_ai_analysis.txt")
    print("="*60)
 
 
def main():
    parser = argparse.ArgumentParser(description="ToTheRoot — AI Penetration Testing Framework")
    parser.add_argument("--target", "-t", required=True, help="Target IP or domain")
    parser.add_argument("--output", "-o", default="scans", help="Output directory")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI analysis")
    parser.add_argument("--model", "-m", default="qwen3.5:4b", help="Ollama model to use")
    args = parser.parse_args()
    run_pipeline(args.target, args.output, args.no_ai, args.model)
 
if __name__ == "__main__":
    main()
 