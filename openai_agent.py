"""Compatibility launcher; configure the live provider through AsterCode CLI.

No ``.env`` file is loaded here and no model name or credential is embedded.
Use ``python -m astercode run ...`` after configuring the environment as
described in ``README.md``.
"""

from astercode.cli import app

if __name__ == "__main__":
    app()
