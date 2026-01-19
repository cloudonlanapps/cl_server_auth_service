import os
from dataclasses import dataclass
from pathlib import Path
from .utils import get_db_url, ensure_cl_server_dir

@dataclass
class AuthConfig:
    cl_server_dir: Path
    database_url: str
    private_key_path: Path
    public_key_path: Path
    admin_username: str
    admin_password: str
    access_token_expire_minutes: int
    algorithm: str = "ES256"
    
    @classmethod
    def from_cli_args(cls, args):
         
        cl_dir = ensure_cl_server_dir(create_if_missing=True)
        return cls(
            cl_server_dir=cl_dir,
            database_url=get_db_url(),
            private_key_path=Path(args.private_key_path) if args.private_key_path else cl_dir / "keys" / "private_key.pem",
            public_key_path=Path(args.public_key_path) if args.public_key_path else cl_dir / "keys" / "public_key.pem",
            admin_username=args.admin_username,
            admin_password=args.admin_password,
            access_token_expire_minutes=args.token_expire_minutes,
        )
