"""Main entry point for the auth service."""

import os
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

import uvicorn
from . import auth_utils, database
from .auth import app
from .config import AuthConfig


class Args(Namespace):
    host: str
    port: int
    debug: bool
    reload: bool
    log_level: str
    database_url: str | None
    private_key_path: str | None
    public_key_path: str | None
    admin_username: str
    admin_password: str
    token_expire_minutes: int
    guest_mode: bool

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8000,
        debug: bool = False,
        reload: bool = False,
        log_level: str = "info",
        database_url: str | None = None,
        private_key_path: str | None = None,
        public_key_path: str | None = None,
        admin_username: str = "admin",
        admin_password: str = "admin",
        token_expire_minutes: int = 30,
    ) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.debug = debug
        self.reload = reload
        self.log_level = log_level
        self.database_url = database_url
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.token_expire_minutes = token_expire_minutes


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
        default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help="Log level (default: info)",
    )
    _ = parser.add_argument(
        "--database-url",
        default=None,
        help="Database URL",
    )
    _ = parser.add_argument(
        "--private-key-path",
        default=None,
        help="Path to private key",
    )
    _ = parser.add_argument(
        "--public-key-path",
        default=None,
        help="Path to public key",
    )
    _ = parser.add_argument(
        "--admin-username",
        default="admin",
        help="Default admin username",
    )
    _ = parser.add_argument(
        "--admin-password",
        default="admin",
        help="Default admin password",
    )
    _ = parser.add_argument(
        "--token-expire-minutes",
        type=int,
        default=30,
        help="Access token expiration in minutes",
    )

    args = parser.parse_args(namespace=Args())

    cl_server_dir = os.environ.get("CL_SERVER_DIR")
    if not cl_server_dir:
        print("Error: CL_SERVER_DIR environment variable not set", file=sys.stderr)
        return 1

    try:
        config = AuthConfig.from_cli_args(args, cl_server_dir)
        
        # Initialize dependencies
        database.init_db(config)
        auth_utils.load_keys(config)
        
        # Configure app
        # Note: We can't support reload with dependency injection via app state easily w/o factory
        app.state.config = config

        # Print startup info
        print("=" * 70)
        print("                    Auth Service Starting")
        print("=" * 70)
        print(f"Host:               {args.host}")
        print(f"Port:               {args.port}")
        print(f"Log Level:          {args.log_level}")
        print(f"Database:           {config.database_url}")
        print(f"CL_SERVER_DIR:      {cl_server_dir}")
        print("=" * 70)
        print()

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level=args.log_level,
        )
        return 0
    except Exception as e:
        print(f"Error starting service: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
