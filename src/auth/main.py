"""Main entry point for the auth service."""

import sys
from argparse import ArgumentParser, Namespace

import uvicorn
from cl_server_shared import Config


class Args(Namespace):
    host: str
    port: int
    debug: bool
    reload: bool
    log_level: str

    def __init__(
        self,
        host: str = "",
        port: int = 0,
        debug: bool = False,
        reload: bool = False,
        log_level: str = "info",
    ) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.debug = debug
        self.reload = reload
        self.log_level = log_level


def main() -> int:
    """Start the auth service.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    parser = ArgumentParser(description="Start the authentication service")
    _ = parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    _ = parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to (default: 8000)",
    )
    _ = parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload (development mode)",
    )
    _ = parser.add_argument(
        "--log-level",
        default=Config.LOG_LEVEL.lower(),
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help=f"Log level (default: {Config.LOG_LEVEL.lower()})",
    )

    args = parser.parse_args(namespace=Args())

    # Print startup info
    print("=" * 70)
    print("                    Auth Service Starting")
    print("=" * 70)
    print(f"Host:               {args.host}")
    print(f"Port:               {args.port}")
    print(f"Reload:             {args.reload}")
    print(f"Log Level:          {args.log_level}")
    print(f"Database:           {Config.AUTH_DATABASE_URL}")
    print(f"CL_SERVER_DIR:      {Config.CL_SERVER_DIR}")
    print("=" * 70)
    print()

    try:
        # Note: Using single worker since auth uses SQLite (WAL mode)
        # For production with PostgreSQL, you can add --workers support
        uvicorn.run(
            "auth:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level=args.log_level,
        )
        return 0
    except Exception as e:
        print(f"Error starting service: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
