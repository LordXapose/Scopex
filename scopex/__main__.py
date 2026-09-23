"""
SCOPEX package entry point.

Allows SCOPEX to be executed with:

    python -m scopex
"""

from scopex.cli.main import app


if __name__ == "__main__":
    app()