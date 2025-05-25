import dns.resolver
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from time import time
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from rich.panel import Panel
import socks
from time import sleep
from core.utils import clear_console, load_wordlist

console = Console()

class DNSScanner:
    def __init__(self):
        self.resolvers = [
            '8.8.8.8',    # Google
            '1.1.1.1',    # Cloudflare
            '9.9.9.9',    # Quad9
            '208.67.222.222'  # OpenDNS
        ]
        self.default_ports = {
            'socks4': 1080,
            'socks5': 1080,
            'http': 8080
        }
    
    def configure_proxy(self, proxy_type, proxy_host, proxy_port=None):
        """Konfigurasi proxy jaringan"""
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
            console.print(f"[green]✓ Proxy {proxy_type}://{proxy_host}:{proxy_port} configured")
            return True
        except Exception as e:
            console.print(f"[red]× Proxy error: {str(e)}")
            return False

    def dns_query(self, domain, retries=2, timeout=2):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [random.choice(self.resolvers)]
        resolver.use_tcp = True  # Untuk kompatibilitas proxy
        resolver.timeout = timeout
        resolver.lifetime = timeout + 1

        for _ in range(retries + 1):
            try:
                answers = resolver.resolve(domain, 'A')
                return str(answers[0])
            except dns.resolver.NXDOMAIN:
                return None
            except dns.resolver.NoAnswer:
                return None
            except Exception:
                sleep(0.5)
        return None

    def scan_target(self, target, subdomains, progress, task):
        found = []
        for sub in subdomains:
            progress.console.print(f"Scanning {sub}.{target}...", style="yellow")
            progress.update(task, advance=1)
            domain = f"{sub}.{target}"
            ip = self.dns_query(domain)
            if ip:
                found.append((domain, ip))
        return target, found

def run_subdomain_scanner():
    clear_console()
    scanner = DNSScanner()
    console.print(Panel.fit("[bold]🚀 ENHANCED SUBDOMAIN SCANNER[/]", style="cyan", padding=(1,2)))

    # Konfigurasi Proxy
    if console.input("[bold]Use proxy? (y/N): [/]").lower() == 'y':
        proxy_type = console.input("[bold]Proxy type (socks4/socks5/http): [/]").strip().lower()
        proxy_host = console.input("[bold]Proxy host: [/]").strip()
        proxy_port = console.input(f"[bold]Proxy port [{'default' if scanner.default_ports.get(proxy_type) else 'required'}]: [/]").strip()
        scanner.configure_proxy(proxy_type, proxy_host, proxy_port or None)

    # Load wordlist
    wordlist = load_wordlist()
    if not wordlist:
        console.print("[red]× Wordlist tidak ditemukan!")
        return

    # Input target
    targets_input = console.input("[bold]Target domains (e.g, example.com): [/]")
    targets = list({t.strip() for t in targets_input.split(',') if '.' in t})
    if not targets:
        console.print("[red]× Format target tidak valid!")
        return

    # Setup progress bar
    total_tasks = len(targets) * len(wordlist)
    progress = Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console=console
    )
    
    found = defaultdict(list)
    start_time = time()
    
    with progress:
        task = progress.add_task(f"Scanning {len(targets)} target(s)", total=total_tasks)
        
        with ThreadPoolExecutor(max_workers=50) as executor:  # Adjust workers for efficiency
            futures = []
            for target in targets:
                futures.append(
                    executor.submit(
                        scanner.scan_target,
                        target,
                        wordlist,
                        progress,
                        task
                    )
                )
            
            for future in as_completed(futures):
                target, results = future.result()
                found[target].extend(results)

    # Hasil scanning
    console.print(f"\n[bold green]✓ Scan selesai dalam {time()-start_time:.2f} detik[/]")
    for target, subs in found.items():
        console.print(f"\n[bold]Hasil untuk [cyan]{target}[/]:")
        for domain, ip in subs:
            console.print(f"  [green]✓ {domain.ljust(40)} [yellow]{ip}")
        
        # Save to file
        filename = f"subdomains_{target.replace('.','_')}.txt"
        with open(filename, 'w') as f:
            f.write("\n".join(f"{d}\t{i}" for d,i in subs))
        console.print(f"[bright_black]  ↳ Disimpan ke [yellow]{filename}")

    console.print(f"\n[bold]Total subdomain ditemukan: {sum(len(v) for v in found.values())}")
