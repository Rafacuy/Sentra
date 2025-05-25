import requests
import os
import sys
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from colorama import init, Fore, Style
from core.utils import clear_console

def load_wordlist(path: str) -> list:
    """Load directory wordlist from a file."""
    if not os.path.isfile(path):
        console.print(f"[red]Wordlist file not found:[/red] {path}")
        sys.exit(1)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        words = [line.strip() for line in f if line.strip()]
    return words

def save_report(found: list, report_path: str):
    """Save found URLs to report file."""
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            for url in found:
                f.write(url + '\n')
        console.print(f"[green]Report saved to[/green] {report_path}")
    except Exception as e:
        console.print(f"[red]Failed to save report:[/red] {e}")

def scan_directories(base_url: str, wordlist: list, extensions: list) -> list:
    """Scan for directories and files at base_url using given wordlist and extensions."""
    found = []
    total_tasks = len(wordlist) * len(extensions)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning", total=total_tasks)
        for word in wordlist:
            for ext in extensions:
                path = f"{word}{ext}"
                url = urljoin(base_url.rstrip('/') + '/', path)
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        console.print(f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} {url}")
                        found.append(url)
                except requests.RequestException:
                    pass  # ignore timeouts and connection errors
                progress.update(task, advance=1)
    return found

def main():
    clear_console()
    
    init(autoreset=True)
    console.print(Panel.fit("[b]󰛡 Directory Bruteforcer Tool[/b]", 
                         style="#ffffff", padding=(1,2)))
    console.print("[yellow]Enter the target URL (e.g., https://example.com):[/yellow] ", end='')
    base_url = input().strip()
    if not base_url.startswith(('http://', 'https://')):
        console.print("[red]Invalid URL. Please include http:// or https://[/red]")
        sys.exit(1)

    wordlist_path = os.path.join('wordlists', 'directory-brute.txt')
    report_path = 'dir_reports.txt'
    extensions = ['/', '.php', '.html', '.asp', '.aspx', '.js', '.txt', '.bak']

    words = load_wordlist(wordlist_path)
    found_urls = scan_directories(base_url, words, extensions)

    if found_urls:
        save_report(found_urls, report_path)
    else:
        console.print("[yellow]No directories or files found." )

console = Console()

def run_bruteforce():
    main()

