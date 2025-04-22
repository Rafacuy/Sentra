# modules/subdomain.py
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from core.utils import clear_console

console = Console()

def check_subdomain(sub, target):
    domain = f"{sub}.{target}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.resolve(domain, 'A')
        return (domain, str(answers[0]))
    except:
        return None

def run_subdomain_scanner(wordlist):
    clear_console()
    console.print(Panel.fit("[b] Subdomain Discovery Engine[/b]", style="#74b9ff", padding=(1, 2)))

    targets_input = console.input("\n[bold]  Enter target domains (e.g, example.com): [/]")
    targets = [t.strip() for t in targets_input.split(',') if t.strip()]
    
    total_tasks = len(targets) * len(wordlist)
    found = defaultdict(list)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        transient=False
    ) as progress:
        task = progress.add_task(f"[#74b9ff]Scanning targets...", total=total_tasks)

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {}
            for target in targets:
                for sub in wordlist:
                    future = executor.submit(check_subdomain, sub, target)
                    futures[future] = target

            for future in as_completed(futures):
                target = futures[future]
                progress.update(task, advance=1)
                try:
                    result = future.result()
                    if result:
                        found[target].append(result)
                        progress.stop()
                        console.print(f"[green]• {result[0]}[/] [bright_black]({target})[/]")
                        progress.start()
                except:
                    continue

    for target, results in found.items():
        filename = f"subdomains_{target.replace('.', '_')}.txt"
        with open(filename, 'w') as f:
            for domain, ip in results:
                f.write(f"{domain}\t{ip}\n")
        console.print(f"\n[bold green]󰨙 Report for [yellow]{target}[/] saved to [yellow]{filename}[/]")

    console.print(f"\n[bold green]󰄴 Total found subdomains: {sum(len(v) for v in found.values())}")
