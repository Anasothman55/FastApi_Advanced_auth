import uuid
from typing import Callable, Optional, Any
from datetime import datetime, timezone, timedelta
from functools import wraps

from fastapi.responses import JSONResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from passlib.context import CryptContext
from dataclasses import dataclass

from fastapi import HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt, JWTError, ExpiredSignatureError# type: ignore
from pydantic import EmailStr

from ..db.models import UserModel
from ..core.config import setting
from ..db.redis import redis_manager



#? hash and verify password
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password_utils(password: str) -> str:
  return pwd.hash(password)
def verify_password_utils(plain_password: str, hash_password: str) -> bool:
  return pwd.verify(plain_password, hash_password)



def error_schema(body: str, field: str):
  return {
    "type": "UniqueViolation",
    "loc": [ body],
    "msg": f"{body} already exists",
    "input": field
  }



#? create url safe token with itsdangerous library
serializer = URLSafeTimedSerializer(
  secret_key=setting.SECRET_KEY,
  salt="email-config"
)

def create_url_safe_token(data: dict):
  token = serializer.dumps(data)
  return token

def decode_url_safe_token(token: str, max_age: int = 3600 * 24)-> dict:
  try:
    return serializer.loads(token, max_age=max_age)
  
  except SignatureExpired:
    
    raise HTTPException(
      status_code= status.HTTP_401_UNAUTHORIZED,
      detail={"message": "Token has expired"}
    )
  except BadSignature:
    
    raise HTTPException(
      status_code= status.HTTP_401_UNAUTHORIZED,
      detail={"message": "Invalid token"}
    )


#? token
def create_token_schema( data:dict, expires_delta: timedelta | None = None, token: str ='ac'):
  to_encod = data.copy()
  current_time= datetime.now(timezone.utc)
  
  if token == 'ac':
    expire = current_time + expires_delta if expires_delta else current_time + timedelta(minutes=15)
    to_encod.update({"refresh": False})
  else:
    expire = current_time + expires_delta if expires_delta else current_time + timedelta(days=30)
    to_encod.update({"refresh": True})
  
  to_encod.update({"exp": expire})
  encoded_jwt = jwt.encode(to_encod, setting.SECRET_KEY, algorithm=setting.ALGORITHM)
  return encoded_jwt

async def create_token(token_dict: dict ,response: Response):
  """ rhis method to create a new token and store refresh token in redis and access token in cookie"""
  atuid = str(uuid.uuid4())
  rtuid = str(uuid.uuid4())
  
  access_token_expire = timedelta(minutes=setting.ACCESS_TOKEN_EXPIRE_MINUTES)
  access_token = create_token_schema(
    data={**token_dict, "atuid": atuid, "rtuid": rtuid},
    expires_delta=access_token_expire,
    token='ac'
  )
  
  user_uid = str(token_dict.get("sub"))
  refresh_token_expire = timedelta(days=setting.REFRESH_TOKEN_EXPIRE_DAYS)
  refresh_token = create_token_schema(
    data={"sub": user_uid, "rtuid": rtuid},
    expires_delta=refresh_token_expire,
    token='rt'
  )

  await redis_manager.store_refresh_token(
    user_id=user_uid, refresh_token=refresh_token,ttl_days=setting.REFRESH_TOKEN_EXPIRE_DAYS)
  
  response.set_cookie(
    key="access_token",
    value= access_token,
    httponly=True,
    secure=False,  # Added secure flag for HTTPS
    samesite='lax'  # Added samesite protection
  )
  
  response.set_cookie(
    key="refresh_token",
    value=refresh_token,
    httponly=True,
    secure=False,
    samesite="lax",
  )
  
  return {
    "access_token": access_token,
    "refresh_token": refresh_token,
    "status": True
  }

async def refresh_token_utils(token_dict, rtuid, response: Response):
  atuid = str(uuid.uuid4())
  
  access_token_expire = timedelta(minutes=setting.ACCESS_TOKEN_EXPIRE_MINUTES)
  access_token = create_token_schema(
    data={**token_dict, "atuid": atuid, "rtuid": rtuid},
    expires_delta=access_token_expire,
    token='ac'
  )
  

  response.set_cookie(
    key="access_token",
    value= access_token,
    httponly=True,
    secure=False,
    samesite='lax'  
  )
  
  return {
    "access_token": access_token,
    "status": True
  }

def jwt_decode(token: str, options: dict | None = None):
  try:
    if options:
      payload = jwt.decode(token, setting.SECRET_KEY,algorithms= setting.ALGORITHM, options=options)
    else:
      payload = jwt.decode(token, setting.SECRET_KEY, algorithms=setting.ALGORITHM)
    return payload
  except ExpiredSignatureError as e:
    raise HTTPException(status_code= status.HTTP_403_FORBIDDEN, detail=str(e))
  except JWTError as e:
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
  except Exception as e:
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

#? check token data
@dataclass
class CheckAccessTokenData:
  sub: str
  email: EmailStr
  atuid: str
  rtuid: str
  exp: int
  refresh: bool
  user: UserModel | None = None
  get_user_by_uid: Callable[[uuid.UUID], Optional[UserModel]] = None
  db: AsyncSession = None
  
  async def validate(self):
    credentials_exception = HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Could not validate credentials",
    )
    
    if not all([self.sub, self.email, self.atuid, self.rtuid, self.exp]):
      raise credentials_exception

    user_data = await self.get_user_by_uid(uuid.UUID(self.sub))

    if not user_data:
      raise credentials_exception

    self.user = user_data

    if not self.user.is_active:
      raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="User is inactive. Please contact support.",
      )


@dataclass
class CheckRefreshTokenData:
  rrf: dict
  
  def validate(self) -> dict:
    credentials_exception = HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Could not validate credentials",
    )
    
    rfdata = ["sub", "rtuid", "exp", "refresh"]
    if not all(rfdata):
      raise credentials_exception
    return dict(self.rrf)


#? user repository
class UserRepositoryUtils:
  def __init__(self, db: AsyncSession):
    self.db = db
    self.model = UserModel
  async def _statement(self,  field: str, value: Any):
    statement = (
      select(self.model).where(getattr(self.model, field) == value)
    )
    
    result = await self.db.execute(statement)
    user =  result.scalars().first()
    return user
  async def get_by_email(self, email: EmailStr) -> UserModel:
    return await self._statement("email", email)
  
  async def get_by_username(self, username: str) -> UserModel:
    return await self._statement("username", username)
  
  async def get_by_uid(self, uid: uuid.UUID) -> UserModel:
    return await self._statement("uid", uid)

  async def create(self, **kwargs):
    new_user = self.model(**kwargs)
    self.db.add(new_user)
    await self.db.commit()
    await self.db.refresh(new_user)
    return new_user




def handle_exceptions(func):
  @wraps(func)
  async def wrapper(*args, **kwargs):
    try:
      return await func(*args, **kwargs)  
    except HTTPException as e:
      raise e
    except Exception as e:
      raise HTTPException(status_code=500, detail=str(e)) from e
    
  return wrapper