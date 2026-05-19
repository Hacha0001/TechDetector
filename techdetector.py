import requests
from bs4 import BeautifulSoup
import json
import re
import sys
from rich.console import Console
from rich.table import Table
import argparse

__version__ = "1.2.0"

console = Console()

# Simple vulnerability database (you can expand this)
VULN_DB = {
    "WordPress": ["5.8.0", "5.9.0", "6.0.0", "6.1.0"],   # Example vulnerable versions
    "jQuery": ["1.0", "1.12.0", "2.2.0", "3.0.0", "3.1.0", "3.2.0", "3.3.0", "3.4.0"],
    "Bootstrap": ["3.0.0", "3.1.0", "4.0.0"]
}

class TechDetector:
    def __init__(self):
        with open('fingerprints.json', 'r') as f:
            self.fingerprints = json.load(f)
        
        self.headers = {
            'User-Agent': f'TechDetector/{__version__}'
        }

    def extract_version(self, text, patterns):
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match and match.group(1):
                return match.group(1)
        return None

    def is_vulnerable(self, tech, version):
        if not version or tech not in VULN_DB:
            return False, "Unknown"
        vulnerable_versions = VULN_DB[tech]
        for vuln in vulnerable_versions:
            if version.startswith(vuln):
                return True, "High"
        return False, "Low"

    def detect_technologies(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        response = requests.get(url, headers=self.headers, timeout=15, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = response.text

        detected = {}

        for tech, data in self.fingerprints.items():
            confidence = 0
            reasons = []
            version = None

            # Header check
            for hname, hval in response.headers.items():
                for pat in data.get("headers", []):
                    if re.search(pat, hval, re.I):
                        confidence += 40
                        reasons.append(f"Header: {hname}")

            # HTML check
            for pat in data.get("html", []):
                if re.search(pat, text, re.I):
                    confidence += 35
                    reasons.append(f"HTML: {pat}")

            # Version Detection
            if "version_patterns" in data:
                version = self.extract_version(text, data["version_patterns"])
                if version:
                    confidence += 20
                    reasons.append(f"Version: {version}")

            if confidence > 30:
                is_vuln, risk = self.is_vulnerable(tech, version)
                detected[tech] = {
                    "confidence": min(confidence, 100),
                    "categories": data.get("categories", ["Other"]),
                    "version": version or "Unknown",
                    "vulnerable": is_vuln,
                    "risk": risk,
                    "reasons": list(set(reasons))[:4]
                }
        
        return detected, response.url, len(response.text)//1024

    def print_results(self, detected, final_url, size):
        console.print(f"\n[bold green]✅ Analysis Complete:[/bold green] {final_url} | Size: {size} KB\n")
        
        table = Table(title=f"TechDetector v{__version__} - Technology Detection")
        table.add_column("Technology", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("Risk", style="red")
        table.add_column("Categories", style="magenta")
        table.add_column("Evidence", style="dim")

        for tech, info in sorted(detected.items(), key=lambda x: x[1]['confidence'], reverse=True):
            risk_color = "[bold red]" if info['vulnerable'] else "[green]"
            risk_text = f"{risk_color}{info['risk']}[/]" if info['vulnerable'] else "[green]Safe[/]"
            
            table.add_row(
                tech,
                info['version'],
                risk_text,
                ", ".join(info['categories']),
                ", ".join(info['reasons'])
            )
        
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="TechDetector - Advanced Version & Vulnerability Scanner")
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-o", "--output", help="Save report as JSON")
    parser.add_argument("-v", "--version", action="store_true")

    args = parser.parse_args()

    if args.version:
        console.print(f"[bold blue]TechDetector v{__version__}[/bold blue]")
        sys.exit(0)

    console.print(f"[bold blue]🔍 TechDetector v{__version__} - Technology + Vulnerability Scanner[/bold blue]\n")

    if not args.url:
        url = console.input("[bold]Enter URL: [/bold]").strip()
        if not url:
            console.print("[red]No URL provided.[/red]")
            sys.exit(1)
    else:
        url = args.url

    detector = TechDetector()
    detected, final_url, size = detector.detect_technologies(url)
    detector.print_results(detected, final_url, size)


if __name__ == "__main__":
    main()