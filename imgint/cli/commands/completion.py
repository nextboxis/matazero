from __future__ import annotations

import click
from rich.console import Console

console = Console(highlight=False)

@click.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str) -> None:
    """Generate shell completion scripts (bash, zsh, fish)."""
    if shell == "bash":
        console.print('# bash completion for matazero\neval "$(_MATAZERO_COMPLETE=bash_source matazero)"')
    elif shell == "zsh":
        console.print('# zsh completion for matazero\neval "$(_MATAZERO_COMPLETE=zsh_source matazero)"')
    elif shell == "fish":
        console.print('# fish completion for matazero\neval (env _MATAZERO_COMPLETE=fish_source matazero)')
