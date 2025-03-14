from asyncpg.pgproto.pgproto import timedelta
from fastapi import FastAPI
from fastapi.responses import  JSONResponse

from slowapi.errors import RateLimitExceeded

from contextlib import  asynccontextmanager

from .middleware.auth import RefreshTokenMiddleware
from .root import roots
from .db.index import init_db, close_db_connection, get_db
from app import limiter

from datetime import datetime,timezone

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


app = FastAPI(title="FastAPI Project", version="0.1.0", lifespan=life_span)


app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_error(request, exc):

  return JSONResponse(
    status_code=429,
    content={
      "error": "Rate limit exceeded",
      "message": "You have exceeded the allowed number of requests. Please try again later.",
      "retry_after": f"Retry after {exc.detail}"
    }
  )

app.add_middleware(RefreshTokenMiddleware)




app.include_router(roots)



