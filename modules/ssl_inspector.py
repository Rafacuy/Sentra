# modules/ssl_inspector.py
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.progress import Progress
from rich.style import Style
from core.utils import clear_console

console = Console()

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
        'subject': {},
        'issuer': {},
        'sans': [],
        'key_size': 'Unknown',
        'sig_algorithm': cert.signature_algorithm_oid._name,
        'extensions': {}
    }

    # Parse subject
    for attr in cert.subject:
        details['subject'][attr.oid._name] = attr.value
    
    # Parse issuer
    for attr in cert.issuer:
        details['issuer'][attr.oid._name] = attr.value
    
    # Parse SANs
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        details['sans'] = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    
    # Get public key size
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        details['key_size'] = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        details['key_size'] = pub_key.curve.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        details['key_size'] = pub_key.key_size
    
    # Parse important extensions
    extensions = [
        ('Basic Constraints', x509.BasicConstraints),
        ('Key Usage', x509.KeyUsage),
        ('Extended Key Usage', x509.ExtendedKeyUsage),
        ('Certificate Policies', x509.CertificatePolicies),
        ('CRL Distribution Points', x509.CRLDistributionPoints),
        ('Authority Information Access', x509.AuthorityInformationAccess)
    ]
    
    for name, ext_class in extensions:
        try:
            ext = cert.extensions.get_extension_for_class(ext_class)
            details['extensions'][name] = ext.value
        except x509.ExtensionNotFound:
            continue
    
    return details

def check_protocol_support(host: str, port: int) -> Dict[str, bool]:
    """Check supported SSL/TLS protocols"""
    protocols = {
        'SSLv2': False,
        'SSLv3': False,
        'TLSv1.0': False,
        'TLSv1.1': False,
        'TLSv1.2': True,  # Assume supported as we connected with default context
        'TLSv1.3': False
    }
    
    with Progress(transient=True) as progress:
        task = progress.add_task("[cyan]Testing protocols...", total=5)
        
        # Test SSLv3
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ctx.options &= ~ssl.OP_NO_SSLv3
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(3)
                s.connect((host, port))
                protocols['SSLv3'] = True
        except: pass
        progress.update(task, advance=1)
        
        # Test TLSv1.0
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.connect((host, port))
                protocols['TLSv1.0'] = True
        except: pass
        progress.update(task, advance=1)
        
        # Test TLSv1.1
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.connect((host, port))
                protocols['TLSv1.1'] = True
        except: pass
        progress.update(task, advance=1)
        
        # TLSv1.3 (detect if actually used)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.connect((host, port))
                if s.version() == 'TLSv1.3':
                    protocols['TLSv1.3'] = True
        except: pass
        progress.update(task, advance=1)
    
    return protocols

def analyze_cipher(cipher: Tuple) -> Dict:
    """Analyze cipher strength and vulnerabilities"""
    name, version, bits = cipher
    analysis = {
        'strength': 'Strong',
        'recommendation': 'Secure',
        'color': 'green',
        'details': []
    }
    
    # Bit length check
    if bits < 128:
        analysis['strength'] = 'Weak'
        analysis['recommendation'] = 'Upgrade immediately'
        analysis['color'] = 'red'
    elif 128 <= bits < 256:
        analysis['strength'] = 'Moderate'
        analysis['recommendation'] = 'Consider upgrading'
        analysis['color'] = 'yellow'
    
    # Vulnerable cipher check
    weak_patterns = ['RC4', 'DES', 'MD5', 'SHA1', 'CBC', 'EXPORT', 'NULL']
    for pattern in weak_patterns:
        if pattern in name.upper():
            analysis['details'].append(f"Potential vulnerability: {pattern}")
            analysis['color'] = 'red' if 'RC4' in pattern else analysis['color']
    
    if 'GCM' in name or 'CHACHA20' in name:
        analysis['details'].append("Using modern encryption (AEAD)")
    
    return analysis

def run_ssl_inspector():
    clear_console()
    console.print(Panel.fit("[b]󰅂 SSL/TLS Inspector[/b] v2.1", 
                          style="#55efc4", padding=(1,2)))
    
    while True:
        target = console.input("\n[bold]󰅂  Enter target (example.com or example.com:443): [/] ").strip()
        
        if not target:
            console.print("[yellow]Please enter a target host[/yellow]")
            continue
            
        # Parse host and port
        if ':' in target:
            host, port_str = target.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                console.print(f"[red]Invalid port number: {port_str}[/red]")
                continue
        else:
            host = target
            port = 443
        
        # Resolve hostname
        ip = resolve_host(host)
        if not ip:
            console.print("[yellow]Try again or press Ctrl+C to exit[/yellow]")
            continue
            
        try:
            # Establish connection
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(10)
                with console.status("[bold green]Performing SSL handshake...[/]", spinner="bouncingBall"):
                    s.connect((host, port))
                
                cert_der = s.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                cipher = s.cipher()
                
                # Get detailed certificate info
                cert_details = get_certificate_details(cert)
                
                # Protocol support check
                protocols = check_protocol_support(host, port)
                
                # Cipher analysis
                cipher_analysis = analyze_cipher(cipher)
                
                # Certificate transparency check
                try:
                    ct_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
                    ct_status = "[green]󱂬 Certificate Transparency registered[/green]"
                except x509.ExtensionNotFound:
                    ct_status = "[yellow]󰀔 No SCT detected (Certificate Transparency)[/yellow]"
                
                # Validity period
                not_after = cert.not_valid_after
                validity_days = (not_after - datetime.utcnow()).days
                
                # Build output
                console.print(f"\n[bold]Target:[/] {host}:{port} [dim]({ip})[/]")
                
                # Certificate details panel
                cert_info = (
                    f"[bold]Domain:[/] {cert_details['subject'].get('commonName', 'N/A')}\n"
                    f"[bold]Organization:[/] {cert_details['subject'].get('organizationName', 'N/A')}\n"
                    f"[bold]Issuer:[/] {cert_details['issuer'].get('organizationName', 'N/A')}\n"
                    f"[bold]SANS:[/] {', '.join(cert_details['sans'][:3])}{'...' if len(cert_details['sans']) > 3 else ''}\n"
                    f"[bold]Key Algorithm:[/] {cert_details['sig_algorithm']}\n"
                    f"[bold]Key Size:[/] {cert_details['key_size']} bit"
                )
                console.print(
                    Panel.fit(
                        cert_info,
                        title="Certificate Info",
                        style="#55efc4",
                        padding=(1, 2)
                    )
                )
                
                # Security analysis panel
                security_table = Table(
                    show_header=False,
                    style="bright_white",
                    expand=True
                )
                security_table.add_column("Category", style="bold #55efc4", width=20)
                security_table.add_column("Status", width=50)
                
                # Protocol status
                proto_status = []
                for proto, supported in protocols.items():
                    status = "[green]✓[/green]" if supported else "[red]✗[/red]"
                    proto_status.append(f"{proto}: {status}")
                security_table.add_row("Protocols", "\n".join(proto_status))
                
                # Cipher status
                cipher_status = (
                    f"{cipher[0]}\n"
                    f"Strength: [{cipher_analysis['color']}]{cipher_analysis['strength']}[/]\n"
                    + "\n".join(cipher_analysis['details'])
                )
                security_table.add_row("Cipher Suite", cipher_status)
                
                # Validity status
                validity_style = "green" if validity_days > 30 else "yellow" if validity_days > 0 else "red"
                security_table.add_row("Validity", 
                                    f"[{validity_style}]{not_after.strftime('%Y-%m-%d')} "
                                    f"({validity_days} days remaining)[/{validity_style}]")
                
                security_table.add_row("Certificate Transparency", ct_status)
                
                console.print(
                    Panel.fit(
                        security_table,
                        title="Security Analysis",
                        style="#55efc4",
                        padding=(1, 2)
                    )
                )
                
                console.print(f"\n[dim]Scan completed at {datetime.now().strftime('%H:%M:%S')}[/]")
                break

        except socket.timeout:
            console.print("[bold red]Connection timeout: Server is not responding[/bold red]")
        except ConnectionRefusedError:
            console.print(f"[bold red]Connection refused: Port {port} may be closed[/bold red]")
        except ssl.SSLError as e:
            console.print(f"[bold red]SSL Error: {str(e)}[/bold red]")
            if "certificate verify failed" in str(e):
                console.print("[yellow]Tip: The server certificate is invalid or self-signed[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Unexpected Error: {str(e)}[/bold red]")
        
        console.print("[yellow]Try again or press Ctrl+C to exit[/yellow]")