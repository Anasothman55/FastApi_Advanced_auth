from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from .db.redis import redis_manager

limiter = Limiter(key_func= get_remote_address)