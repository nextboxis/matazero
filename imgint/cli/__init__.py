"""CLI package for imgint."""

def __getattr__(name: str):
    if name in ("cli", "main"):
        from imgint.cli.main import cli, main
        return cli if name == "cli" else main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["cli", "main"]
