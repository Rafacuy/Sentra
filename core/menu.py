# core/menu.py
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
import os

console = Console()

def show_menu():

    menu_options = [
        ("1", "Subdomain Discovery"),
        ("2", "SSL/TLS Inspector"),
        ("3", "Web Vulnerability Scanner"),
        ("4", "Security Header Audit"),
        ("5", "Website Scraper"),
        ("6", "Admin Page Finder"),
        ("7", "Directory BruteForcer"),
        ("8", "Exit")
    ]

    lines = []
    for number, label in menu_options:
        lines.append(f"[bold red][  {number}  ][/bold red] [white]{label}[/white]")

    menu_text = "\n".join(lines)

    panel = Panel(
        Align.center(menu_text, vertical="middle"),
        title="[bold white]Options[/bold white]",
        border_style="bright_red",
        padding=(1, 4),
        width=60
    )

    console.print(panel)
    return console.input("\n[bold red][  +  ] Select one of the available options (1-8): [/] ")


