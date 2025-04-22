# modules/ssl_inspector.py
import socket
import ssl
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns

console = Console()

def run_ssl_inspector():
    console.clear()
    console.print(Panel.fit("[b]󰅂 SSL/TLS Inspector[/b]", 
                             style="#55efc4", padding=(1,2)))
    
    target = console.input("\n[bold]󰅂  Enter target host (e.g., example.com): [/] ").strip()
    
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            cipher = s.cipher()
            
            # Certificate Info
            cert_info = Table.grid(expand=True)
            cert_info.add_row(
                Panel.fit(
                    f"[bold]Issued To:[/] {cert['subject'][0][0][1]}\n"
                    f"[bold]Issuer:[/] {cert['issuer'][0][0][1]}\n"
                    f"[bold]Valid From:[/] {cert['notBefore']}\n"
                    f"[bold]Valid Until:[/] {cert['notAfter']}",
                    title="Certificate Details",
                    style="#55efc4"
                )
            )
            
            # Security Check
            analysis = Table(
                title="Security Analysis",
                style="bright_white",
                show_header=False
            )
            analysis.add_column("Check", style="bold #55efc4")
            analysis.add_column("Result")
            
            # Protocol
            protocol = s.version()
            protocol_status = (
                "[red]󰀦 Insecure (SSLv2/SSLv3)[/red]" 
                if protocol in ['SSLv2', 'SSLv3'] else 
                "[green]󱂬 Secure (TLS 1.2+)[/green]"
            )
            analysis.add_row("Protocol Version", protocol_status)
            
            # Cipher
            cipher_strength = (
                "[green]󱂬 Strong (256-bit+)[/green]" 
                if cipher[2] >= 256 else 
                "[yellow]󰀔 Moderate (128-bit)[/yellow]" 
                if cipher[2] >= 128 else 
                "[red]󰀦 Weak (64-bit or less)[/red]"
            )
            analysis.add_row("Cipher Strength", cipher_strength)
            
            # Expiry
            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_remaining = (expiry_date - datetime.now()).days
            expiry_status = (
                f"[green]󱂬 {days_remaining} days remaining[/green]" 
                if days_remaining > 30 else 
                f"[yellow]󰀔 {days_remaining} days remaining[/yellow]" 
                if days_remaining > 0 else 
                "[red]󰀦 Certificate Expired[/red]"
            )
            analysis.add_row("Certificate Expiry", expiry_status)
            
            console.print(Columns([cert_info, analysis]))

    except Exception as e:
        console.print(f"[bold red]⨯  Connection Error: {str(e)}[/bold red]")
