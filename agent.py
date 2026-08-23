"""Compatibility launcher for the AsterCode CLI.

The production entrypoint lives in ``src/astercode``; this file remains only
for users who previously ran ``python agent.py`` from the starter project.
"""

from astercode.cli import app

if __name__ == "__main__":
    app()
