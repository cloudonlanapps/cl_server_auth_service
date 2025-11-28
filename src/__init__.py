"""CoLAN Auth Server."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from . import models, database, routes, config, service, schemas


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create default admin if not exists
    db = database.SessionLocal()
    try:
        user_service = service.UserService(db)
        admin = user_service.get_user_by_username(config.ADMIN_USERNAME)
        if not admin:
            print(f"Creating default admin user: {config.ADMIN_USERNAME}")
            admin_create = schemas.UserCreate(
                username=config.ADMIN_USERNAME,
                password=config.ADMIN_PASSWORD,
                is_admin=True,
                permissions=["*"],  # Grant all permissions
            )
            user_service.create_user(admin_create)
    finally:
        db.close()

    yield

    # Shutdown: cleanup if needed
    pass


app = FastAPI(title="User Auth Service", version="0.1.0", lifespan=lifespan)

app.include_router(routes.router)
