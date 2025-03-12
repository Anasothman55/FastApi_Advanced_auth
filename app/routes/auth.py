

from typing import Annotated, List
from fastapi import  APIRouter, Query, Response, status, Form,Depends,HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import  EmailStr

from ..db.models import UserModel
from ..db.index import get_db
from ..schema.auth import CreateIUserDict,GetFullUser
from ..crud.auth import (
  register_crud,
  verify_email_crud,
  logout_crud,
  login_crud,
  refresh_token_crud,
  reset_password_crud,
  forgot_password_crud
)

from ..utils.auth import UserRepositoryUtils, handle_exceptions
from ..dependencies.auth import get_user_repo, get_current_user, get_all_token

from rich import print


route = APIRouter(tags=["auth"])




@route.post("/signup", status_code= status.HTTP_201_CREATED)
@handle_exceptions
async def signup_route(
    user_model: Annotated[CreateIUserDict, Form()],
    db: Annotated[AsyncSession, Depends(get_db)],
    user_repo: Annotated[UserRepositoryUtils,  Depends(get_user_repo)],
):
  result = await register_crud(db, user_model, user_repo)
  print(result)
  return result


@route.get("/verify", status_code= status.HTTP_202_ACCEPTED)
async def verify_user_route(
    token : Annotated[str , Query(...)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
  result = await verify_email_crud(db, token)
  if isinstance(result, RedirectResponse):
    return result
  return result

@route.post("/login", status_code= status.HTTP_202_ACCEPTED)
@handle_exceptions
async def login_route(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_db)],
    response: Response
):

  response = await login_crud(db,form_data,response)
  return response



@route.post("/logout", status_code= status.HTTP_204_NO_CONTENT)
@handle_exceptions
async def logout_route(
    current_user: Annotated[UserModel, Depends(get_current_user)],
    token: Annotated[dict, Depends(get_all_token)],
    response: Response
):
  result = await logout_crud(**token, response=response)
  return result

@route.get('/refresh_token', status_code= status.HTTP_201_CREATED,)
@handle_exceptions
async def refresh_token_route(
    token: Annotated[dict, Depends(get_all_token)], response: Response):
  result = await refresh_token_crud(**token, response=response)
  return result


@route.get('/me', response_model=GetFullUser, status_code=status.HTTP_200_OK)
async def get_user_me_router( current_user: Annotated[UserModel, Depends(get_current_user)]):
  try:
    json_data = jsonable_encoder(current_user.model_dump())
    return json_data
  except Exception as e:
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@route.post('/forgot_password', status_code= status.HTTP_202_ACCEPTED)
@handle_exceptions
async def forgot_password_route(
    email: Annotated[EmailStr, Form(...)],
    user_repo: Annotated[UserRepositoryUtils,  Depends(get_user_repo)],
):
  result = await forgot_password_crud(user_repo,email)
  return result


@route.put("/reset-password", status_code=status.HTTP_202_ACCEPTED)
@handle_exceptions
async def reset_password_route(
    token: Annotated[str, Query(...)],
    new_password: Annotated[str, Form(..., min_length=8, max_length=128)],
    db: Annotated[AsyncSession, Depends(get_db)]
):
  result = await reset_password_crud(db,token, new_password)
  return result








