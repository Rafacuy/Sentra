# modules/header_audit.py
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.style import Style
from core.utils import clear_console

console = Console()


def run_header_audit():
    clear_console()
    console.print(Panel.fit("[b]󰝸 Security Headers Auditor[/b]", 
                             style="#a29bfe", padding=(1,2)))
    
    url = console.input("\n[bold]󰅂  Enter target URL (e.g., https://example.com): [/] ").strip()

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        # Daftar header keamanan penting
        security_headers = {
            "Content-Security-Policy": {"status": "critical", "recommendation": "Implement CSP to prevent XSS"},
            "Strict-Transport-Security": {"status": "high", "recommendation": "Enforce HTTPS connections"},
            "X-Content-Type-Options": {"status": "medium", "recommendation": "Set to 'nosniff'"},
            "X-Frame-Options": {"status": "high", "recommendation": "Prevent clickjacking attacks"},
            "X-XSS-Protection": {"status": "medium", "recommendation": "Enable XSS filtering"},
            "Referrer-Policy": {"status": "low", "recommendation": "Control referrer information"},
            "Feature-Policy": {"status": "medium", "recommendation": "Restrict browser features"},
            "Permissions-Policy": {"status": "medium", "recommendation": "Manage permissions"}
        }

        report = Table(
            title=f"Security Headers Audit for {url}",
            style="bright_white",
            show_header=True,
            header_style=Style(color="#a29bfe", bold=True),
            expand=True
        )
        report.add_column("Header", style="bold #a29bfe", width=25)
        report.add_column("Status", width=15)
        report.add_column("Recommendation", width=50)

        for header, info in security_headers.items():
            status = (
                "[green]󱂬 Present[/green]" 
                if header in headers else 
                "[red] Missing[/red]"
            )
            report.add_row(
                f"[bold]{header}[/]",
                status,
                info["recommendation"]
            )

        console.print(Panel.fit(report, title="Audit Report", style="#a29bfe", padding=(1,2)))

    except Exception as e:
        console.print(f"[bold red]  Error: {str(e)}[/bold red]")
