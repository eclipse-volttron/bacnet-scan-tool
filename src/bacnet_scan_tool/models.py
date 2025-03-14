from sqlmodel import SQLModel, Field
from typing import Optional
from pydantic import BaseModel

class Device(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    ip_address: str

class Point(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    device_id: int
    name: str

class Tag(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    point_id: int
    name: str

# Pydantic request models
class CreateTagRequest(BaseModel):
    name: str

class WritePointValueRequest(BaseModel):
    value: str
