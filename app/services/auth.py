


from ..utils.auth import (
  error_schema,
  UserRepositoryUtils,
  create_url_safe_token,
  verify_password_utils,
  jwt_decode,
  CheckRefreshTokenData,
  decode_url_safe_token
)
from ..schema.auth import CreateIUserDict, CreateUser
from ..email.auth import UserAuthEmail
from ..db.models import UserModel
from ..db.redis import redis_manager, RedisError
from ..utils import response_result

from fastapi import HTTPException, status
from pydantic import ValidationError, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession


from typing import List 
import uuid
from rich import print




#! register services
async def unique_validation(db: AsyncSession,email: EmailStr, username: str) -> List[dict]:
  """* a private methods that are used to validate the uniqueness of the email and username """
  user_repo = UserRepositoryUtils(db)
  errors = []
  if existing_username :=  await user_repo.get_by_username(username):
    errors.append(error_schema("username", existing_username.username))
  if existing_email := await user_repo.get_by_email(email):
    errors.append(error_schema("email", existing_email.email))
  return errors

async def validate_user_data(db: AsyncSession,user: CreateIUserDict) -> CreateUser:
  errors = []
  result = None
  try:
    user_data = CreateUser(**user.model_dump())
  except ValidationError as pe:
    errors.extend(pe.errors())
  else:
    result = user_data

  unique_errors = await unique_validation(db, user.email, user.username)
  if unique_errors:
    errors.extend(unique_errors)

  
  if errors:
    raise HTTPException(
      status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
      detail=response_result(
        success=False,
        message="Invalid user data",
        data=errors
      )
    )

  return result

#! verify code service
async def get_email_service(token:  str, user_repo: UserRepositoryUtils):
  user_email = decode_url_safe_token(token).get('email')
  user = await user_repo.get_by_email(user_email)
  
  return user

#! send email services
async def send_verify_email( email: EmailStr, username: str)-> dict[str:str]:
  serializer = {"email": email}
  verify_token = create_url_safe_token(serializer)
  
  datadict = {
    "verify_url": f"http://127.0.0.1:8000/auth/verify?token={verify_token}",
    "username": username,
    "company_name": "Monix"
  }
  
  response = await UserAuthEmail.send_verification_email([email], datadict)
  return response


#! login services
async def authenticate_user(user_repo: UserRepositoryUtils, email: EmailStr, password: str) -> UserModel:
  user = await user_repo.get_by_email(email)
  
  if not user:
    raise HTTPException(
      status_code=status.HTTP_404_NOT_FOUND,
      detail= response_result(
        success=False,
        message="User not found",
        data={
          "error": "User not found",
          "hint": "Please check the email address",
          "loc":"email"
        }
      )
    )
  
  if password != user.password:
    if not verify_password_utils(password, user.password):
      raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=response_result(
          success=False,
          message="Invalid password",
          data={
            "error": "Invalid password",
            "hint": "Please check your password",
            "loc":"password"
          }
        )
      )
  return user



#! logout services
async def access_token_decode(access_token: str) -> uuid.UUID:
  access_token_decode = jwt_decode(access_token)
  user_uid = str(access_token_decode.get("sub"))
  return user_uid

async def redis_delete_refresh_token(user_uid: uuid.UUID, refresh_token: str):
  try:
    redis_refresh_token = await redis_manager.get_refresh_token(user_uid)
      
    if redis_refresh_token != refresh_token:
      raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "Invalid refresh token"}
      )
    
    redis_payload = jwt_decode(redis_refresh_token)
    await redis_manager.delete_refresh_token(user_uid)
    await redis_manager.blacklist_refresh_token(redis_payload.get('rtuid'))
  except RedisError as e:
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))



#! refresh token service
async def decode_uid(access_token)-> tuple:
  payload = jwt_decode(access_token, options={"verify_exp": False})
  user_uid = payload.get("sub")
  at_rtuid = payload.get("rtuid")
  email = payload.get("email")
  return user_uid, at_rtuid,email

async def get_redis_refresh_token(user_uid: uuid.UUID,at_rtuid: uuid.UUID, refresh_token: str):
  redis_refresh_token = await redis_manager.get_refresh_token(user_uid)
  
  redis_refresh_payload = CheckRefreshTokenData(jwt_decode(redis_refresh_token)).validate()
  rrp_rtuid = redis_refresh_payload.get('rtuid')
  await redis_manager.is_token_blacklisted(rrp_rtuid)
  
  refresh_token_payload = CheckRefreshTokenData(jwt_decode(refresh_token)).validate()
  rt_user_uid = refresh_token_payload.get('sub')
  rt_rtuid = refresh_token_payload.get('rtuid')
  await redis_manager.is_token_blacklisted(rt_rtuid)
    
  if redis_refresh_token != refresh_token:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail={
        "error": "Invalid refresh token you refresh token and server refresh token don't match"
      })
  if user_uid != rt_user_uid or at_rtuid != rt_rtuid:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error": "Token mismatch: Access token and refresh token details do not match."}
    )
  
  return rt_rtuid



#! forget password service
async def send_reset_password_email(email: str, username: str):
  serializer = {"email": email}
  reset_token = create_url_safe_token(serializer)
  datadict = {
    "reset_url": f"http://127.0.0.1:8000/auth/reset-password?token={reset_token}",
    "username": username,
    "company_name": "Monix"
  }
  msg = "Password reset email sent successfully. Please check your email address."
  response = await UserAuthEmail.send_reset_password_email([email], datadict, msg)
  return response


async def reset_password_service(
  token: str, user_repo: UserRepositoryUtils, new_password: str):
  await redis_manager.is_password_reset_token_blacklisted(token)

  user_email = dict(decode_url_safe_token(token)).get('email', None)
  user = await user_repo.get_by_email(user_email)

  if not user.is_verified:
    return HTTPException(
      status_code=status.HTTP_403_FORBIDDEN,
      detail="Your account is not verified. Please verify your account."
    )

  password_match = verify_password_utils(new_password, user.password)

  if password_match:
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail="You cannot use the same password as the current password."
    )
  
  await redis_manager.blacklist_password_reset_token(token)

  return user









