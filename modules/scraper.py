# modules/scraper.py
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from core.utils import clear_console

console = Console()

def run_scraper():
    clear_console()
    console.print(Panel.fit("[b]Website Scraping Engine[/b]", 
                            style="#51CBD1", padding=(1,2)))
    
    url = console.input("Enter the website URL to scrape (e.g., https://example.com): ").strip()

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')

        # Judul
        title = soup.title.string if soup.title else "No Title"
        console.print(f"\n[bold green]Website:[/bold green] {url}")
        console.print(f"[bold cyan]Title:[/bold cyan] {title}\n")

        # Konten teks
        console.print(f"[bold magenta]Text Content:[/bold magenta]")
        text_content = soup.get_text(separator='\n', strip=True)
        console.print(text_content, justify="left")

        # Paragraf
        console.print(f"\n[bold yellow]Paragraphs:[/bold yellow]")
        paragraphs = soup.find_all('p')
        if not paragraphs:
            console.print("[italic dim]No <p> tags found.[/italic dim]")
        for idx, para in enumerate(paragraphs, 1):
            console.print(f"[bold blue]Para {idx}:[/bold blue] {para.get_text(strip=True)}")

        # Tautan
        console.print(f"\n[bold red]Links:[/bold red]")
        links = soup.find_all('a', href=True)
        if not links:
            console.print("[italic dim]No <a> tags with href found.[/italic dim]")
        for link in links:
            console.print(f"[bold green]Link:[/bold green] {link.get('href')} [dim]({link.text})[/dim]")

    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]⨯ Error:[/bold red] {e}")
