from app.db.models import UserModel
from ..utils.auth import UserRepositoryUtils, jwt_decode, CheckAccessTokenData
from ..db.index import get_db

from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from typing import Annotated

async def get_user_repo(db: Annotated[AsyncSession, Depends(get_db)]):
  return UserRepositoryUtils(db)


async def get_access_token(request: Request):
  access_token = request.cookies.get("access_token")
  if not access_token:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Access Token is missing",
    )
  return access_token

async def get_refresh_token(request: Request):
  refresh_token = request.cookies.get("refresh_token")
  if not refresh_token:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Refresh Token is missing",
    )
  return refresh_token

async def get_all_token(
  access_token: Annotated[str, Depends(get_access_token)],
  refresh_token: Annotated[str, Depends(get_refresh_token)]
):
  return {
    "access_token": access_token,
    "refresh_token": refresh_token
  }


async def check_token_exist(
    access_token: Annotated[str, Depends(get_access_token)] ,request: Request):
  payload = jwt_decode(access_token)
  if payload.get('refresh', False):
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="You cannot use the refresh token as access token",
    )
  
  return payload

async def get_current_user(
    payload: Annotated[str, Depends(check_token_exist)],
    db: Annotated[AsyncSession, Depends(get_db)],
    user_repo: Annotated[UserRepositoryUtils, Depends(get_user_repo)]
)-> UserModel:

  token_data = CheckAccessTokenData(**payload, get_user_by_uid=user_repo.get_by_uid, db=db)
  await token_data.validate()
  return token_data.user