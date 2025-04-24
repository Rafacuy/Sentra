# modules/subdomain.py
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import platform
import sys
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress, 
    SpinnerColumn, 
    TextColumn, 
    BarColumn, 
    TimeRemainingColumn,
    TaskProgressColumn
)
from core.utils import clear_console, load_wordlist
from itertools import cycle

console = Console()

def is_termux():
    return 'termux' in sys.executable.lower()

def optimize_for_termux():
    if is_termux():
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        return 20  # Max workers 
    return 50  # Default for desktop

def animated_loading():
    """Animasi loading khusus untuk inisialisasi"""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    with Live(console=console, refresh_per_second=10) as live:
        for frame in cycle(frames):
            live.update(Panel.fit(f"[bold cyan]{frame} Initializing scanner...", border_style="yellow"))
            yield

def check_subdomain(sub, target):
    domain = f"{sub}.{target}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0 if is_termux() else 1.5
        resolver.lifetime = 2.0 if is_termux() else 1.5
        answers = resolver.resolve(domain, 'A')
        return (domain, str(answers[0]))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return None
    except dns.resolver.NoNameservers:
        return (domain, "Nameserver Error")
    except Exception as e:
        return (domain, f"Error: {str(e)}")

def run_subdomain_scanner():
    clear_console()
    
    # Animasi awal
    console.print(Panel.fit("[b]🚀 Subdomain Discovery Engine[/b]", style="#74b9ff", padding=(1, 2)))
      # Trigger animasi awal
    
    wordlist = load_wordlist()
    if not wordlist:
        console.print("[bold red]⨯ No wordlist available![/]")
        return

    targets_input = console.input("\n[bold]  Enter target domains (e.g, example.com): [/]")
    targets = list({t.strip() for t in targets_input.split(',') if t.strip()})
    
    # Optimasi berdasarkan platform
    max_workers = optimize_for_termux()
    total_tasks = len(targets) * len(wordlist)
    found = defaultdict(list)
    errors = []
    
    # Konfigurasi progress bar khusus
    with Progress(
        SpinnerColumn(spinner_name='bouncingBar', style="bold cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        transient=True
    ) as progress:
        main_task = progress.add_task(
            f"[bold cyan]🔍 Scanning {len(targets)} target(s)...", 
            total=total_tasks
        )

        # Buat task untuk setiap target
        target_tasks = {
            target: progress.add_task(
                f"🌐 {target}",
                total=len(wordlist),
                visible=True  # Langsung terlihat
            )
            for target in targets
        }

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_subdomain, sub, target): (sub, target) 
                      for target in targets for sub in wordlist}

            for future in as_completed(futures):
                sub, target = futures[future]
                progress.update(main_task, advance=1)
                progress.update(target_tasks[target], advance=1)
                
                try:
                    result = future.result()
                    if result:
                        domain, ip = result
                        if "Error" not in ip:
                            found[target].append((domain, ip))
                            console.print(
                                f"[green]• {domain}[/] [bright_black]({ip})[/]",
                                highlight=False
                            )
                        else:
                            errors.append(f"{domain}: {ip}")
                except Exception as e:
                    errors.append(f"{sub}.{target}: {str(e)}")

    # Tampilkan ringkasan
    console.print(Panel.fit(
        f"[bold green]✅ Scan completed![/]\n"
        f"• Target: {len(targets)}\n"
        f"• Subdomain found: {sum(len(v) for v in found.values())}\n"
        f"• Error: {len(errors)}",
        style="green"
    ))

    # Simpan hasil dan error
    for target, results in found.items():
        filename = f"subdomains_{target.replace('.', '_')}.txt"
        with open(filename, 'w') as f:
            f.write("\n".join(f"{domain}\t{ip}" for domain, ip in results))
        console.print(f"📁 [bold cyan] Report for [yellow]{target}[/] saved to [yellow]{filename}[/]")
    
    if errors:
        console.print(Panel.fit(
            "[bold red]⚠ Error during scanning:[/]\n" + "\n".join(errors[:5]) + 
            ("\n..." if len(errors) >5 else ""),
            style="red"
        ))

    console.print(f"\n[bold green]󰄴 Process Completed![/]")
    console.print(f"[bright_black]╰─────────────────────────────────────────────[/]")
    
    
    