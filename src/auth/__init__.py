"""CoLAN Auth Server."""


from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import database, routes, schemas, service
from .config import AuthConfig


@asynccontextmanager
async def lifespan(app: FastAPI):
    config: AuthConfig = app.state.config
    # Startup: Create default admin if not exists
    if database.SessionLocal is None:
        print("Warning: Database session factory not initialized")
        yield
        return

    try:
        session = database.SessionLocal()
        try:
            user_service = service.UserService(session)
            admin = user_service.get_user_by_username(config.admin_username)
            if not admin:
                print(f"Creating default admin user: {config.admin_username}")
                admin_create = schemas.UserCreate(
                    username=config.admin_username,
                    password=config.admin_password,
                    is_admin=True,
                    permissions=["*"],  # Grant all permissions
                )
                _ = user_service.create_user(admin_create)
        finally:
            session.close()
    except Exception as e:
        # Handle errors gracefully (e.g., during testing or first-time setup)
        print(f"Warning: Could not create default admin user: {e}")


    yield

    # Shutdown: cleanup if needed
    pass


app = FastAPI(title="User Auth Service", version="0.1.0", lifespan=lifespan)

app.include_router(routes.router)
