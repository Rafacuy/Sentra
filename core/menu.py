# core/menu.py
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

def show_menu():
    menu = Table.grid(padding=(1, 3), expand=True)
    menu.add_column(justify="center")

    options = [
        ("Subdomain Discovery", "#74b9ff"),
        ("SSL/TLS Inspector", "#55efc4"),
        ("Web Vulnerability Scan", "#ff7675"),
        ("Security Headers Audit", "#a29bfe"),
        ("Website Scraping", "#e123fe"),
        ("Exit System", "#d63031")
    ]

    menu.add_row(
        Panel.fit(
            "\n".join(
                f"[{color}]{idx+1}. {text}[/{color}]" 
                for idx, (text, color) in enumerate(options)
            ),
            title="[b]Main Operations[/b]",
            style="bright_white",
            padding=(1, 4)
        )
    )

    console.print(menu)
    return console.input("\n[bold #6C5CE7]󰘔  Select operation (1-6): [/]")
