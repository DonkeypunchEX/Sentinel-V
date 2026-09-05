#!/usr/bin/env python3
"""PyInstaller entry point for the sentinel-v standalone executable.

PyInstaller needs a script that imports the package rather than one
that lives inside it, since ``sentinel_v/cli.py`` uses relative imports
that only resolve when the module is imported as part of the
``sentinel_v`` package (not executed directly as ``__main__``).
"""

from sentinel_v.cli import main

if __name__ == "__main__":
    main()
