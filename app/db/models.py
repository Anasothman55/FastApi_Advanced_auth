from sqlalchemy import DateTime
from sqlmodel import SQLModel,Field,Column
from sqlalchemy.sql import func
import sqlalchemy.dialects.postgresql as pg

import uuid
from datetime import datetime, timezone





class UserModel(SQLModel, table= True):
  __tablename__ = "users"

  uid: uuid.UUID = Field(sa_column=Column(pg.UUID(as_uuid=True), index=True, primary_key=True, default=uuid.uuid4))
  username: str = Field(unique=True, index=True)
  email: str = Field(unique=True, index=True)
  role: str = Field(index= True, default="user")
  is_active: bool = Field(default=True)
  password: str = Field(exclude=True, nullable=True)
  is_verified: bool = Field(default = False)
  last_login_date: datetime = Field(
    sa_column=Column(
      DateTime(timezone=True), nullable=True
    )
  )

  created_at: datetime = Field( sa_column=Column(pg.TIMESTAMP(timezone=True), default=datetime.now(timezone.utc)) )
  updated_at: datetime = Field(
    sa_column=Column(pg.TIMESTAMP(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
  )


  def __repr__(self):
    return f"<Book {self.username}>"



