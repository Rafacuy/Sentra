# sentra.py
# AUTHOR: Rafacuy

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.utils import clear_console, load_wordlist
from core.banner import display_header
from core.menu import show_menu
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from modules import subdomain, ssl_inspector, vulnerability, header_audit, scraper, admin_finder, dir_bruteforcer

console = Console()

def main():
    wordlist = load_wordlist()
    
    while True:
        clear_console()
        
        display_header()
        choice = show_menu()

        if choice == '1':
            subdomain.run_subdomain_scanner()
        elif choice == '2':
            ssl_inspector.run_ssl_inspector()
        elif choice == '3':
            vulnerability.run_vulnerability_scan()
        elif choice == '4':
            header_audit.run_header_audit()
        elif choice == '5':
            scraper.run_scraper()
        elif choice == '6':
            admin_finder.main()
        elif choice == '7':
            dir_bruteforcer.run_bruteforce()       
        elif choice == '8':
            console.print("[bold red]\n  Exiting Sentra... \n[/bold red]")
            sys.exit(0)
        else:
            console.print("[bold red]  Invalid selection![/bold red]")

        console.input("\n[dim]Press Enter to return to main menu...[/dim]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation cancelled by user![/bold red]")
        sys.exit(1)
