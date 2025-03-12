
from redis.asyncio import RedisError # type: ignore
import redis.asyncio as redis # type: ignore
from ..core.config import setting
from datetime import timedelta
from fastapi import HTTPException, status
from typing import Optional



class RedisManager:
  def __init__(self, host:str, port:int, password:str, ssl:bool):
    """Initialize Redis connection with configuration."""
    self.redis = redis.Redis(
      host= host,
      port= port,
      password=password,
      ssl= ssl
    )

    self.REFRESH_TOKEN_PREFIX = "refresh_token:"
    self.BLACKLIST_SET = "blacklist"
    self.PASSWORD_RESET_BLACKLIST = "password_reset_blacklist"


  async def _get_refresh_token_key(self, user_id: str) -> str:
    """Generate Redis key for refresh token."""
    return f"{self.REFRESH_TOKEN_PREFIX}{user_id}"

  async def _decode_token(self, token: bytes) -> Optional[str]:
      """Safely decode token from bytes to string."""
      if not token:
        return None
      try:
        return token.decode("utf-8")
      except UnicodeDecodeError:
        raise HTTPException(
          status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
          detail="Failed to decode token"
        )
  async def store_refresh_token(self, user_id: str, refresh_token: str, ttl_days: int):
    key = await self._get_refresh_token_key(user_id)
    result =  await self.redis.setex(key,timedelta(days= ttl_days), value=refresh_token)
    if not result:
      raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER, detail="An Error in the server")
    return result

  async def get_refresh_token(self, user_id: str) -> str:
    key = await self._get_refresh_token_key(user_id)
    stored_token = await self.redis.get(key)
    if not stored_token:
      raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail= "Invalid or expired refresh token")
    return await self._decode_token(stored_token)

  async def delete_refresh_token(self, user_uid):
    key = await self._get_refresh_token_key(user_uid)
    result= await self.redis.delete(key)
    
    if result == 0:
      raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail= "Invalid or expired refresh token")
    return True
  
  async def blacklist_refresh_token(self, rtuid: str):
    result = await self.redis.sadd(self.BLACKLIST_SET, rtuid)
    if not result:
      raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER, detail= "An Error in the server")
    return 1
  
  async def is_token_blacklisted(self, rtuid: str):
    try:
      result = await self.redis.sismember(self.BLACKLIST_SET, rtuid)
      if result:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token is blacklisted")
      else:
        return 1
    except RedisError as rex:
      raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(rex))

  async def blacklist_password_reset_token(self, token: str):
    result = await self.redis.sadd(self.PASSWORD_RESET_BLACKLIST, token)
    if not result:
      raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER, detail= "An Error in the server")
    return 1

  async def is_password_reset_token_blacklisted(self, token: str):
    try:
      result = await self.redis.sismember(self.PASSWORD_RESET_BLACKLIST, token)
      if result:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Password reset token is blacklisted")
      else:
        return 1
    except RedisError as rex:
      raise HTTPException(status_code = status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(rex))

redis_config = {
  'host': setting.UPSTASH_REDIS_HOST,
  'port': setting.UPSTASH_REDIS_PORT,
  'password': setting.UPSTASH_REDIS_PASSWORD,
  'ssl': setting.UPSTASH_REDIS_SSL
}

# Initialize token manager
redis_manager = RedisManager(**redis_config)


