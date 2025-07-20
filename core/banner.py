# core/banner.py
from rich.console import Console
from time import sleep

console = Console(highlight=False)

def display_header():


        console.print(
            """[red]
_______ _______ __   _ _______  ______ _______
|______ |______ | \  |    |    |_____/ |_____|
______| |______ |  \_|    |    |    \_ |     |

Developed by Rafacuy (arazz.)
            [/red]"""
        )

   
    

if __name__ == '__main__':
    display_header()    

