# core/banner.py
from rich.console import Console
from rich.panel import Panel
from rich.style import Style

console = Console()

def display_header():
    header = """[bold #6C5CE7]
    ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
     ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
     ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                    
        [/bold #6C5CE7]"""
    console.print(Panel.fit(header, 
                            title="v4.0 Professional", 
                            subtitle="by Arazz • Enterprise Security Suite",
                            style=Style(color="#A663CC", bold=True)))
