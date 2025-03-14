
from fastapi import FastAPI

from contextlib import  asynccontextmanager

from .middleware.auth import RefreshTokenMiddleware
from .root import roots
from .db.index import init_db, close_db_connection, get_db

@asynccontextmanager
async def life_span(app: FastAPI):
  try:  
    await init_db()
  except Exception as e:
    print("Error during startup: " + str(e))
    raise
  yield
  try:
    await close_db_connection()
    print("Application shutdown complete")
  except Exception as e:
    print(f"Error closing database connection: {str(e)}")


app = FastAPI(
  title="FastAPI Project",
  description="A FastAPI project template",
  version="0.1.0",
  lifespan=life_span
)

app.add_middleware(RefreshTokenMiddleware)


app.include_router(roots)



