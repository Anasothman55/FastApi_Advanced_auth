from datetime import datetime, date
from pydantic import BaseModel, Field, ConfigDict, EmailStr, StrictStr
import uuid
from enum import Enum
from typing import List,Optional



class RoleBase(str, Enum):
  user = "user"
  admin = "admin"



class UserBase(BaseModel):
  username: StrictStr = Field(...,max_length=128)
  email: EmailStr
  
  model_config = ConfigDict(str_strip_whitespace=True)


class GetFullUser(UserBase):
  uid: uuid.UUID
  role: str
  is_active: bool
  last_login_date: datetime | None = None
  created_at: datetime
  updated_at: datetime
  is_verified: bool

  model_config = ConfigDict(str_strip_whitespace=True,)


class CreateIUserDict(BaseModel):
  username: str | None = None
  email: str | None = None
  password: str | None = None

  model_config = ConfigDict(str_strip_whitespace=True,)


class CreateUser(UserBase):
  password: str = Field(min_length=8, max_length=128)

  model_config = ConfigDict(str_strip_whitespace=True,extra='forbid',)


class UserLogin(BaseModel):
  email: EmailStr
  password: str















