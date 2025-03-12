
from datetime import datetime, timezone

from fastapi import Response, status,HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import EmailStr

from ..db.models import UserModel
from ..schema.auth import CreateIUserDict, CreateUser, UserBase, UserLogin
from ..services.auth import (
  validate_user_data,
  send_verify_email,
  authenticate_user,
  access_token_decode,
  redis_delete_refresh_token,
  decode_uid,
  get_redis_refresh_token,
  send_reset_password_email,
  reset_password_service,
  get_email_service
)
from ..utils.auth import (
  hash_password_utils,
  UserRepositoryUtils,
  create_token,
  refresh_token_utils,
  handle_exceptions
)





#? user sign up function
@handle_exceptions
async def register_crud(db: AsyncSession, user_model: CreateIUserDict,user_repo: UserRepositoryUtils) -> dict:
  
  user = await validate_user_data(db,user_model)

  hashing = hash_password_utils(user.password)
  user_data = user.model_dump()
  user_data['password'] = hashing

  user = await user_repo.create(**user_data)

  response = await send_verify_email(email= user.email,username= user.username)
  return response

#? user verify email function
@handle_exceptions
async def verify_email_crud(db: AsyncSession, token: str):
  try:
    user_repo = UserRepositoryUtils(db)
    user = await get_email_service(token, user_repo)
    
    if user.is_verified:
      return RedirectResponse(url="/")
    
    user.is_verified = True
    await db.commit()
    await db.refresh(user)

    if user:
      return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
          "message": "Email verified successfully. You will be redirected shortly.",
          "redirect_url": "/"  
        }
      )
  except HTTPException as e:
    raise HTTPException(status_code=e.status_code, detail=str(e)) from e
  except Exception as e:
    raise HTTPException(status_code=500, detail=str(e)) from e
#? user login function

@handle_exceptions
async def login_crud(db: AsyncSession,form_data: OAuth2PasswordRequestForm, response: Response):
  form_dict = {
    "email": form_data.username,
    "password": form_data.password
  }
  user_repo = UserRepositoryUtils(db)
  user = await authenticate_user(user_repo,**form_dict)
  
  if not user.is_verified:
    msg = "Your account is not verified. A new verification email has been sent."
    response_data = await send_verify_email(user.email, user.username, msg)
    return JSONResponse(
      status_code=status.HTTP_403_FORBIDDEN,
      content={"detail": response_data}
    )
  
  token_dict = {
    "sub": str(user.uid),
    "email": user.email
  }
  user.last_login_date = datetime.now(timezone.utc)
  await db.commit()
  await db.refresh(user)
  
  result = await create_token(token_dict,response)
  return {"message": result, "user": user}

#? user logout function
@handle_exceptions
async def logout_crud(access_token, refresh_token, response: Response):
  user_uid = access_token_decode(access_token)
  await redis_delete_refresh_token(user_uid, refresh_token)
  
  response.delete_cookie("access_token")
  response.delete_cookie("refresh_token")

#? refresh token function
@handle_exceptions
async def refresh_token_crud(access_token, refresh_token, response: Response):
  user_uid,at_rtuid,email = await decode_uid(access_token)
  rt_rtuid = await get_redis_refresh_token(user_uid, at_rtuid,refresh_token)

  token_dict = {
    "sub": user_uid,
    "email": email,
  }

  result = await refresh_token_utils(token_dict,rt_rtuid, response)
  return result

#? forgot password function
@handle_exceptions
async def forgot_password_crud(user_repo :UserRepositoryUtils, email: EmailStr):
  
  user = await user_repo.get_by_email(email)
  if not user:
    raise HTTPException(
      status_code=status.HTTP_404_NOT_FOUND,
      detail={"error": "User not found", "hint": "Please check the email address", "loc": "email"}
    )
  email = user.email
  username = user.username
  response = await send_reset_password_email(email, username)
  return response

#? reset password function
@handle_exceptions
async def reset_password_crud(db:AsyncSession,token: str, new_password: str):
  user_repo = UserRepositoryUtils(db)
  user = await reset_password_service(token, user_repo, new_password)

  hashing = hash_password_utils(new_password)

  user.password = hashing
  await db.commit()
  await db.refresh(user)

  return JSONResponse(
    status_code=status.HTTP_200_OK,
    content={
      "message": "Password reset successfully. You will be redirected shortly.",
      "redirect_url": "/login"
    }
  )





