import requests
from pathlib import Path
from datetime import datetime
from time import sleep
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich import print
from requests.exceptions import RequestException
from core.utils import clear_console

console = Console()
WORDLIST_PATH = Path("wordlists/admin-panels.txt")
REPORT_FILE = "bug_reports.txt"

def print_banner():
    console.print(Panel.fit("[b]Admin Page Finder[/b]", 
                         style="#51CBD1", padding=(1,2)))

def check_wordlist():
    if not WORDLIST_PATH.exists():
        console.print(f"[bold red]Error:[/bold red] Wordlist not found at {WORDLIST_PATH}", style="bold red")
        return False
    return True

def load_wordlist():
    with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def test_admin_page(url, session):
    try:
        response = session.get(url, timeout=10)
        return response.status_code == 200
    except RequestException:
        return False

def save_report(target_url, found_pages):
    report_content = f"""
{'='*60}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target URL: {target_url}
Found Pages: {len(found_pages)}
{'='*60}\n"""
    
    for page in found_pages:
        report_content += f"- {page}\n"
    
    report_content += "\n\n"
    
    try:
        with open(REPORT_FILE, 'a', encoding='utf-8') as f:
            f.write(report_content)
        console.print(f"\n[bold green]Report saved to {REPORT_FILE}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error saving report: {str(e)}[/bold red]")

def main():
    clear_console()
    print_banner()
    
    if not check_wordlist():
        return
    
    try:
        target_url = console.input("[bold cyan]Enter target URL (e.g., http://example.com/): [/bold cyan]").strip()
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user[/bold red]")
        return
    
    try:
        wordlist = load_wordlist()
        console.print(f"\n[bold green]Loaded {len(wordlist)} paths from wordlist[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error loading wordlist: {str(e)}[/bold red]")
        return
    
    found_pages = []
    session = requests.Session()
    session.headers.update({'User-Agent': 'Admin Login Finder Tool'})
    
    try:
        with Progress(transient=True) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(wordlist))
            
            for path in wordlist:
                if not path.startswith('/'):
                    path = '/' + path
                test_url = urljoin(target_url, path)
                
                progress.update(task, advance=1, description=f"[cyan]Testing: {path}")
                
                if test_admin_page(test_url, session):
                    console.print(f"\n[bold green]Found potential admin page: {test_url}[/bold green]")
                    found_pages.append(test_url)
                
                sleep(0.1)  # Rate limiting
                
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error during scanning: {str(e)}[/bold red]")
    finally:
        session.close()
    
    if found_pages:
        save_report(target_url, found_pages)
    else:
        console.print("\n[bold yellow]No admin pages found[/bold yellow]")

if __name__ == "__main__":
    main()