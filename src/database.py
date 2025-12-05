"""Auth service database setup."""
from cl_server_shared import create_db_engine, create_session_factory, get_db_session
from cl_server_shared.database import Base
from cl_server_shared.config import AUTH_DATABASE_URL as DATABASE_URL

# Create engine with WAL mode (handled by cl_server_shared)
engine = create_db_engine(DATABASE_URL, echo=False)
SessionLocal = create_session_factory(engine)

def get_db():
    """Get database session for FastAPI dependency injection."""
    return get_db_session(SessionLocal)
