# modules/scraper.py
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.utils import clear_console

console = Console()

def extract_metadata(soup):
    """Ekstrak metadata penting dari halaman web"""
    metadata = {
        'title': soup.title.string if soup.title else "No Title",
        'description': '',
        'keywords': '',
        'og': {},
        'general': []
    }

    # Meta tags reguler
    for tag in soup.find_all('meta'):
        if tag.get('name') == 'description':
            metadata['description'] = tag.get('content', '')
        elif tag.get('name') == 'keywords':
            metadata['keywords'] = tag.get('content', '')
        elif tag.get('property'):
            prop = tag.get('property').replace('og:', '')
            metadata['og'][prop] = tag.get('content', '')
        elif tag.get('name') or tag.get('http-equiv'):
            name = tag.get('name') or tag.get('http-equiv')
            metadata['general'].append({
                'name': name,
                'content': tag.get('content', '')
            })

    return metadata

def extract_contacts(text):
    """Ekstrak email dan nomor telepon menggunakan regex"""
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    phone_regex = r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b'
    
    emails = set(re.findall(email_regex, text))
    phones = set(re.findall(phone_regex, text))
    
    return {
        'emails': [email for email in emails if not email.startswith('//')],
        'phones': [''.join(phone) for phone in phones]
    }

def extract_links(soup, base_url):
    """Ekstrak dan kategorikan semua tautan"""
    parsed_base = urlparse(base_url)
    links = {
        'internal': [],
        'external': [],
        'assets': []
    }

    for tag in soup.find_all(['a', 'link', 'img', 'script'], href=True, src=True):
        url = tag.get('href') or tag.get('src')
        if not url:
            continue

        parsed = urlparse(url)
        if parsed.netloc == parsed_base.netloc or not parsed.netloc:
            links['internal'].append(url)
        else:
            if any(url.endswith(ext) for ext in ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif')):
                links['assets'].append(url)
            else:
                links['external'].append(url)

    return links

def display_section(title, data, style):
    """Menampilkan section data dalam panel Rich"""
    table = Table(show_header=False, box=None, padding=(0,1))
    for key, value in data.items():
        table.add_row(f"[b]{key}:[/b]", str(value))
    
    console.print(Panel.fit(
        table,
        title=f"[b]{title}[/b]",
        style=style,
        padding=(1, 2)
    ))

def run_scraper():
    clear_console()
    console.print(Panel.fit("[b]󰛡 Advanced Website Scraping Engine[/b]", 
                         style="#51CBD1", padding=(1,2)))
    
    url = console.input("\nEnter the website URL to scrape (e.g., https://example.com): ").strip()

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.5'
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        text_content = soup.get_text(separator='\n', strip=True)
        
        # Ekstraksi data
        domain_info = urlparse(url)
        metadata = extract_metadata(soup)
        contacts = extract_contacts(text_content)
        links = extract_links(soup, url)
        
        # Tampilkan hasil
        console.print(f"\n[bold reverse]  RESULTS FOR: {url}  [/bold reverse]\n")
        
        # Panel Domain Info
        display_section("Domain Information", {
            "Network Location": domain_info.netloc,
            "Protocol": domain_info.scheme,
            "Path": domain_info.path
        }, "bold cyan")
        
        # Panel Metadata
        meta_table = Table(show_header=False, box=None)
        meta_table.add_row("Title", metadata['title'])
        meta_table.add_row("Description", metadata['description'] or 'N/A')
        meta_table.add_row("Keywords", metadata['keywords'] or 'N/A')
        console.print(Panel.fit(meta_table, title="[b]Metadata[/b]", style="bold green"))
        
        # Panel Kontak
        contact_data = {}
        if contacts['emails']:
            contact_data["Emails"] = "\n".join(contacts['emails'])
        if contacts['phones']:
            contact_data["Phones"] = "\n".join(contacts['phones'])
        
        if contact_data:
            display_section("Contact Information", contact_data, "bold magenta")
        
        # Panel Links
        link_counts = {k: len(v) for k, v in links.items()}
        display_section("Link Statistics", link_counts, "bold yellow")
        
        # Detail Links
        link_table = Table(title="Link Details", box=None)
        link_table.add_column("Type", style="cyan")
        link_table.add_column("Count", style="magenta")
        link_table.add_column("Examples", style="green")
        for link_type, urls in links.items():
            examples = '\n'.join(urls[:3]) + ('\n...' if len(urls) > 3 else '')
            link_table.add_row(link_type.capitalize(), str(len(urls)), examples)
        
        console.print(Panel.fit(link_table, style="bold blue"))
        
        # Advanced Metadata
        if metadata['og']:
            og_table = Table(title="Open Graph Metadata", box=None)
            og_table.add_column("Property", style="cyan")
            og_table.add_column("Content", style="green")
            for prop, content in metadata['og'].items():
                og_table.add_row(prop, content)
            console.print(Panel.fit(og_table, style="bold yellow"))
            
    except requests.exceptions.RequestException as e:
        console.print(f"\n[bold red]⨯ Connection Error:[/bold red] {e}")
    except Exception as e:
        console.print(f"\n[bold red]⨯ Unexpected Error:[/bold red] {e}")

if __name__ == "__main__":
    run_scraper()