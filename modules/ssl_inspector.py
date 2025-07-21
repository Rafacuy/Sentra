# modules/ssl_inspector.py
import socket
import ssl
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from core.utils import clear_console

console = Console()

# --- Helper function to export results ---
def export_results(results: Dict[str, Any], host: str):
    """Asks the user if they want to export the results and saves them."""
    while True:
        choice = console.input("\n[bold]Export results? (json/txt/no): [/]").strip().lower()
        if choice in ['json', 'txt', 'no']:
            break
        console.print("[yellow]Invalid choice. Please enter 'json', 'txt', or 'no'.[/yellow]")

    if choice == 'no':
        return

    filename = f"{host.replace('.', '_')}_ssl_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{choice}"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            if choice == 'json':
                # Custom JSON encoder to handle datetime objects
                class DateTimeEncoder(json.JSONEncoder):
                    def default(self, o):
                        if isinstance(o, datetime):
                            return o.isoformat()
                        if isinstance(o, x509.Certificate):
                            return o.subject.rfc4514_string()
                        return super().default(o)
                json.dump(results, f, indent=4, cls=DateTimeEncoder)
            elif choice == 'txt':
                for key, value in results.items():
                    f.write(f"--- {key.upper()} ---\n")
                    if isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            f.write(f"{sub_key}: {sub_value}\n")
                    elif isinstance(value, list):
                        for item in value:
                            f.write(f"- {item}\n")
                    else:
                        f.write(f"{value}\n")
                    f.write("\n")
        console.print(f"[green]✔ Results exported successfully to [bold]{filename}[/bold][/green]")
    except IOError as e:
        console.print(f"[red]Error exporting results: {e}[/red]")


# --- TLS Score Calculation ---
def calculate_tls_score(results: Dict[str, Any]) -> Tuple[str, int]:
    """Calculates a TLS score based on various security metrics."""
    score = 100
    grade = "A+"

    # Protocol penalties
    if results['protocols'].get('SSLv3', False):
        score -= 40
    if results['protocols'].get('TLSv1.0', False):
        score -= 20
    if results['protocols'].get('TLSv1.1', False):
        score -= 10

    # Cipher strength penalties
    if results['cipher_analysis']['strength'] == 'Weak':
        score -= 30
    elif results['cipher_analysis']['strength'] == 'Moderate':
        score -= 10
    
    # Key size penalties
    key_size = results['certificate_details']['key_size']
    if isinstance(key_size, int) and key_size < 2048:
        score -= 20

    # Validity penalties
    if results['validity']['is_expired']:
        score = 0
    if results['validity']['is_not_yet_valid']:
        score = 0
    if 0 < results['validity']['days_remaining'] <= 14:
        score -= 10

    # Self-signed penalty
    if results['certificate_details'].get('is_self_signed', False):
        score -= 50

    # Incomplete chain penalty
    if not results['chain_details'].get('is_chain_complete', True):
        score -= 20

    # Map score to grade
    if score >= 95: grade = "A+"
    elif score >= 80: grade = "A"
    elif score >= 65: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 35: grade = "D"
    else: grade = "F"
    
    # Cap score at 0
    score = max(0, score)

    return grade, score


def resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to IP address with error handling"""
    try:
        with console.status("[bold green]Resolving DNS...[/]", spinner="earth"):
            return socket.gethostbyname(host)
    except socket.gaierror as e:
        console.print(f"[bold red]DNS Resolution Error: {str(e)}[/bold red]")
        if "Name or service not known" in str(e):
            console.print("[yellow]Tip: Check if the domain name is spelled correctly[/yellow]")
        return None
    except Exception as e:
        console.print(f"[bold red]Unexpected DNS Error: {str(e)}[/bold red]")
        return None

def get_certificate_details(cert: x509.Certificate) -> Dict:
    """Parse X.509 certificate details using cryptography"""
    details = {
        'subject': {attr.oid._name: attr.value for attr in cert.subject},
        'issuer': {attr.oid._name: attr.value for attr in cert.issuer},
        'sans': [],
        'key_size': 'Unknown',
        'sig_algorithm': cert.signature_algorithm_oid._name,
        'extensions': {},
        'is_self_signed': cert.issuer == cert.subject
    }
    
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        details['sans'] = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    
    pub_key = cert.public_key()
    if isinstance(pub_key, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        details['key_size'] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        details['key_size'] = pub_key.curve.key_size
    
    return details

def check_protocol_support(host: str, port: int) -> Dict[str, bool]:
    """Check supported SSL/TLS protocols"""
    protocols = {
        'SSLv3': False, 'TLSv1.0': False, 'TLSv1.1': False,
        'TLSv1.2': False, 'TLSv1.3': False
    }
    
    # TLSv1.2 & TLSv1.3 (modern check)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(3)
            s.connect((host, port))
            version = s.version()
            if version == 'TLSv1.3':
                protocols['TLSv1.3'] = True
                protocols['TLSv1.2'] = True # TLS 1.3 capable servers must support 1.2
            elif version == 'TLSv1.2':
                protocols['TLSv1.2'] = True
    except Exception:
        pass # Will be caught by main connection logic if it fails

    # Test older protocols
    test_protocols = {
        'TLSv1.0': ssl.PROTOCOL_TLSv1,
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
    }
    
    for name, proto in test_protocols.items():
        try:
            ctx = ssl.SSLContext(proto)
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(2)
                s.connect((host, port))
                protocols[name] = True
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            protocols[name] = False
            
    return protocols


def analyze_cipher(cipher: Tuple) -> Dict:
    """Analyze cipher strength and vulnerabilities"""
    name, _, bits = cipher
    analysis = {'strength': 'Strong', 'color': 'green', 'details': []}
    
    if bits < 128:
        analysis.update({'strength': 'Weak', 'color': 'red'})
    elif 128 <= bits < 256:
        analysis.update({'strength': 'Moderate', 'color': 'yellow'})
    
    weak_patterns = ['RC4', '3DES', 'MD5', 'CBC', 'EXPORT', 'NULL']
    for pattern in weak_patterns:
        if pattern in name.upper():
            analysis['details'].append(f"Contains weak element: {pattern}")
            analysis['color'] = 'red'
    
    if 'GCM' in name or 'CHACHA20' in name:
        analysis['details'].append("Uses modern AEAD encryption")
    
    return analysis

# --- Certificate Chain Check ---
def check_certificate_chain(sock: ssl.SSLSocket) -> Dict:
    """Retrieves and analyzes the certificate chain."""
    chain_details = {'chain': [], 'is_chain_complete': False, 'chain_length': 0}
    try:
        # Get the full chain in DER format
        der_certs = sock.getpeercert(True)
        pem_certs = [ssl.DER_cert_to_PEM_cert(der) for der in der_certs]
        
        chain = [x509.load_pem_x509_certificate(c.encode(), default_backend()) for c in pem_certs]
        chain_details['chain'] = chain
        chain_details['chain_length'] = len(chain)

        # Basic validation: Check if issuer of cert N matches subject of cert N+1
        is_ordered = all(
            chain[i].issuer == chain[i+1].subject for i in range(len(chain) - 1)
        )
        
        # A chain is considered complete if the last cert is self-signed (root CA)
        last_cert_is_root = chain[-1].issuer == chain[-1].subject
        
        if is_ordered and last_cert_is_root:
            chain_details['is_chain_complete'] = True

    except Exception as e:
        chain_details['error'] = str(e)
        
    return chain_details

def run_ssl_inspector():
    clear_console()
    console.print(Panel.fit("[b]🔒 SSL/TLS Inspector[/b] v3.0", 
                          style="bold #00a8ff", border_style="#00a8ff", padding=(1,2)))
    
    while True:
        target = console.input("\n[bold]➤ Enter target (e.g., google.com): [/]").strip()
        
        if not target:
            console.print("[yellow]Please enter a target host.[/yellow]")
            continue
            
        host, port = (target.split(':', 1) + ['443'])[:2]
        try:
            port = int(port)
        except ValueError:
            console.print(f"[red]Invalid port: {port}[/red]")
            continue
        
        ip = resolve_host(host)
        if not ip:
            continue
            
        # This will hold all our results for display and export
        scan_results = {}

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(10)
                with console.status("[bold green]Performing SSL handshake...[/]", spinner="bouncingBall"):
                    s.connect((host, port))
                
                # --- Main Data Collection ---
                cert_der = s.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                scan_results['host_info'] = {'host': host, 'port': port, 'ip': ip}
                scan_results['certificate_details'] = get_certificate_details(cert)
                scan_results['protocols'] = check_protocol_support(host, port)
                scan_results['cipher'] = s.cipher()
                scan_results['cipher_analysis'] = analyze_cipher(s.cipher())
                scan_results['chain_details'] = check_certificate_chain(s)
                
                # --- NEW: Enhanced Validity Check ---
                not_after = cert.not_valid_after_utc
                not_before = cert.not_valid_before_utc
                now = datetime.utcnow()
                scan_results['validity'] = {
                    'not_valid_after': not_after,
                    'not_valid_before': not_before,
                    'days_remaining': (not_after - now).days,
                    'is_expired': now > not_after,
                    'is_not_yet_valid': now < not_before
                }
                
                # --- TLS Score ---
                grade, score = calculate_tls_score(scan_results)
                scan_results['tls_score'] = {'grade': grade, 'score': score}

                # --- Build and Print Output ---
                console.rule(f"[bold]Scan Report for {host}:{port}[/bold]", style="#00a8ff")
                
                # Score Panel
                score_color = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}.get(grade, "red")
                console.print(
                    Panel(f"[{score_color} bold]{grade}[/]", title="[bold]Overall Grade[/]", 
                          style=score_color, width=20, height=3, padding=(0, 4))
                )

                # Certificate Panel
                cert_details = scan_results['certificate_details']
                cert_info = (
                    f"[bold]Common Name:[/] {cert_details['subject'].get('commonName', 'N/A')}\n"
                    f"[bold]SANs:[/] {', '.join(cert_details['sans'][:3])}{'...' if len(cert_details['sans']) > 3 else ''}\n"
                    f"[bold]Issuer:[/] {cert_details['issuer'].get('organizationName', 'N/A')}\n"
                )
                if cert_details['is_self_signed']:
                    cert_info += "[bold red]⚠️ Self-Signed Certificate[/bold red]\n"
                
                console.print(Panel(cert_info, title="[bold #00a8ff]Certificate[/]", expand=False))

                # Details Table
                details_table = Table(show_header=False, box=None, padding=(0, 1))
                details_table.add_column(style="bold #00a8ff")
                details_table.add_column()

                # Validity
                validity = scan_results['validity']
                validity_style = "green" if validity['days_remaining'] > 30 else "yellow" if validity['days_remaining'] > 0 else "red"
                validity_text = f"[{validity_style}]Expires in {validity['days_remaining']} days ({validity['not_valid_after'].strftime('%Y-%m-%d')})[/{validity_style}]"
                if validity['is_expired']:
                    validity_text = "[bold red]❌ Certificate has expired![/bold red]"
                if validity['is_not_yet_valid']:
                    validity_text = f"[bold red]⚠️ Certificate not valid until {validity['not_valid_before'].strftime('%Y-%m-%d')}[/bold red]"
                details_table.add_row("Validity", validity_text)

                # Protocols
                proto_status = ' '.join([f"[{'green' if supported else 'red'}]{p.replace('TLSv', '1.')}[/]" for p, supported in scan_results['protocols'].items()])
                details_table.add_row("Protocols", proto_status)

                # Cipher
                cipher_analysis = scan_results['cipher_analysis']
                cipher_text = f"[{cipher_analysis['color']}]{scan_results['cipher'][0]} ({scan_results['cipher'][2]} bits)[/{cipher_analysis['color']}]"
                details_table.add_row("Cipher Suite", cipher_text)

                # Chain
                chain = scan_results['chain_details']
                chain_color = "green" if chain['is_chain_complete'] else "yellow"
                chain_text = f"[{chain_color}]{chain['chain_length']} certs found. Chain complete: {chain['is_chain_complete']}[/{chain_color}]"
                details_table.add_row("Cert Chain", chain_text)

                console.print(Panel(details_table, title="[bold #00a8ff]Security Details[/]", expand=False))
                
                export_results(scan_results, host)
                break

        except ssl.SSLCertVerificationError as e:
            console.print(f"[bold red]SSL Certificate Error: {e.args[0]}[/bold red]")
            console.print("[yellow]The server's certificate could not be verified. It might be self-signed, expired, or issued by an untrusted CA.[/yellow]")
        except socket.timeout:
            console.print("[bold red]Connection timeout: Server is not responding.[/bold red]")
        except ConnectionRefusedError:
            console.print(f"[bold red]Connection refused: Port {port} may be closed.[/bold red]")
        except ssl.SSLError as e:
            console.print(f"[bold red]SSL Error: {str(e)}[/bold red]")
        except Exception as e:
            console.print(f"[bold red]An unexpected error occurred: {type(e).__name__} - {e}[/bold red]")
        
        if console.input("\n[bold]Scan another target? (y/n): [/]").strip().lower() != 'y':
            break

if __name__ == "__main__":
    run_ssl_inspector()
