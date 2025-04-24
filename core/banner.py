# core/banner.py
from rich.console import Console

console = Console()

def display_header():
    console.print("""
[bold #D50000]         __  ______                                          [/bold #D50000]
[bold #D50000]         \ \/ / ___|  ___ __ _ _ __  _ __   ___ _ __         [/bold #D50000]
[bold #D50000]          \  /\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|        [/bold #D50000]
[bold #D50000]          /  \ ___) | (_| (_| | | | | | | |  __/ |           [/bold #D50000]
[bold #D50000]         /_/\_\____/ \___\__,_|_| |_|_| |_|\___|_|           [/bold #D50000]
[bold #D50000]                                                             [/bold #D50000]
""")

    console.print("""
[bold white]            Develop by Arazz[/bold white]
[white]            TikTok: @rafardhancuy[/white]
[white]            GitHub: https://github.com/Rafacuy[/white]
""")
    console.print("[bright_black]---------------------------------------------------------------[/bright_black]")

