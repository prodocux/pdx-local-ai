"""Entry point for python -m pdx_local_ai.service."""

import sys
from .stdio_transport import main

if __name__ == "__main__":
    sys.exit(main())
