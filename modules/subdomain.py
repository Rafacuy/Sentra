import dns.resolver
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from time import time, sleep
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
import socks
import itertools
from core.utils import clear_console, load_wordlist

console = Console()

def chunked(iterable, size):
    """Splits an iterable into chunks of a given size."""
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk

class DNSScanner:
    """
    A class to perform DNS scanning, with support for proxies and efficient,
    multi-threaded subdomain enumeration.
    """
    def __init__(self):
        self.resolvers = [
            '8.8.8.8',        # Google
            '1.1.1.1',        # Cloudflare
            '9.9.9.9',        # Quad9
            '208.67.222.222'  # OpenDNS
        ]
        self.default_ports = {
            'socks4': 1080,
            'socks5': 1080,
            'http': 8080
        }

    def configure_proxy(self, proxy_type, proxy_host, proxy_port=None):
        """Configures a network proxy for all subsequent socket operations."""
        try:
            proxy_port = int(proxy_port) if proxy_port else self.default_ports.get(proxy_type, 1080)
            proxy_map = {
                'socks4': socks.SOCKS4,
                'socks5': socks.SOCKS5,
                'http': socks.HTTP
            }
            socks.set_default_proxy(
                proxy_map[proxy_type],
                proxy_host,
                proxy_port
            )
            socket.socket = socks.socksocket
            console.print(f"[green]✓ Proxy {proxy_type}://{proxy_host}:{proxy_port} configured[/green]")
            return True
        except Exception as e:
            console.print(f"[red]× Proxy error: {str(e)}[/red]")
            return False

    def dns_query(self, domain, retries=2, timeout=2):
        """
        Performs a DNS 'A' record query for a given domain.

        Args:
            domain (str): The domain to resolve.
            retries (int): Number of times to retry on failure.
            timeout (int): Timeout for the DNS query in seconds.

        Returns:
            str: The resolved IP address, or None if resolution fails.
        """
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [random.choice(self.resolvers)]
        resolver.timeout = timeout
        resolver.lifetime = timeout + 1

        for _ in range(retries + 1):
            try:
                answers = resolver.resolve(domain, 'A')
                if answers:
                    return str(answers[0])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                # These are expected failures for non-existent domains, continue to next try
                sleep(0.1)
                continue
            except Exception:
                # Catch any other unexpected exceptions
                sleep(0.5)
        return None

    def scan_batch(self, target_domain, batch, table):
        """
        Scans a single batch of subdomains for a target domain.

        Args:
            target_domain (str): The main domain (e.g., 'example.com').
            batch (list): A list of subdomains to test.
            table (rich.table.Table): The live table to add results to.

        Returns:
            list: A list of tuples containing (found_domain, ip_address).
        """
        found_results = []
        for sub in batch:
            full_domain = f"{sub}.{target_domain}"
            ip = self.dns_query(full_domain)
            if ip:
                # Add to the live table for real-time display
                table.add_row(full_domain, ip, style="bright_green")
                found_results.append((full_domain, ip))
        return found_results

def run_subdomain_scanner():
    """Main function to run the subdomain scanner tool."""
    clear_console()
    scanner = DNSScanner()
    console.print(Panel.fit("[bold]🚀 SUBDOMAIN SCANNER[/]", style="cyan", padding=(1, 2)))

    # Optional Proxy Configuration
    if console.input("[bold]Use proxy? (y/N): [/]").lower() == 'y':
        proxy_type = console.input("[bold]Proxy type (socks4/socks5/http): [/]").strip().lower()
        proxy_host = console.input("[bold]Proxy host: [/]").strip()
        proxy_port = console.input(f"[bold]Proxy port (default: {scanner.default_ports.get(proxy_type, 'N/A')}): [/]").strip()
        scanner.configure_proxy(proxy_type, proxy_host, proxy_port or None)

    # Load wordlist
    wordlist = load_wordlist()
    if not wordlist:
        console.print("[red]× Wordlist could not be loaded. Exiting.[/red]")
        return

    # Input target(s)
    targets_input = console.input("[bold]Enter target domains (comma-separated, e.g., example.com): [/]")
    targets = list({t.strip() for t in targets_input.split(',') if '.' in t})
    if not targets:
        console.print("[red]× No valid target domains entered. Exiting.[/red]")
        return

    # --- Configuration for Batching & Threading ---
    BATCH_SIZE = 500
    MAX_WORKERS = 50 
    
    batches = list(chunked(wordlist, BATCH_SIZE))
    console.print(f"[cyan]Wordlist loaded: {len(wordlist)} subdomains, split into {len(batches)} batches of ~{BATCH_SIZE}.[/cyan]")

    # --- Setup Live Table for Streaming Results ---
    results_table = Table(title="Discovered Subdomains")
    results_table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    results_table.add_column("IP Address", justify="left", style="magenta")
    
    all_found = defaultdict(list)
    start_time = time()

    with Live(results_table, refresh_per_second=4, console=console) as live:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Create a list of all tasks (target, batch) to submit
            tasks = [(target, batch) for target in targets for batch in batches]
            
            # Submit all tasks to the executor
            future_to_batch = {executor.submit(scanner.scan_batch, target, batch, live.renderable): (target, batch) for target, batch in tasks}

            # Process results as they complete
            for future in as_completed(future_to_batch):
                target, _ = future_to_batch[future]
                try:
                    results_from_batch = future.result()
                    if results_from_batch:
                        all_found[target].extend(results_from_batch)
                except Exception as exc:
                    console.print(f'[red]× A batch generated an exception: {exc}[/red]')

    # --- Final Summary and Save Results ---
    total_found_count = sum(len(v) for v in all_found.values())
    scan_duration = time() - start_time
    
    console.print("\n" + "="*50)
    console.print(f"[bold green]✓ Scan Complete![/bold green]")
    console.print(f"  [+] Duration: {scan_duration:.2f} seconds")
    console.print(f"  [+] Total Subdomains Found: {total_found_count}")
    console.print("="*50 + "\n")

    if total_found_count > 0:
        for target, subs in all_found.items():
            filename = f"found_subdomains_{target.replace('.','_')}.txt"
            console.print(f"[bold]Saving results for [cyan]{target}[/cyan] to [yellow]{filename}[/yellow]...")
            try:
                with open(filename, 'w') as f:
                    f.write(f"Subdomain scan results for {target}\n")
                    f.write("\n".join(f"{domain}\t{ip}" for domain, ip in subs))
                console.print(f"[green]  ✓ Successfully saved.[/green]")
            except IOError as e:
                console.print(f"[red]  × Error saving file: {e}[/red]")

if __name__ == '__main__':
    run_subdomain_scanner()
