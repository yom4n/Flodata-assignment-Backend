from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, Field, ConfigDict
from bson import ObjectId

# Custom Pydantic type for MongoDB ObjectId
class PydanticObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError('Invalid ObjectId')
        return str(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type='string')

# Token models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

# Student models
class StudentBase(BaseModel):
    name: str
    roll_number: str
    class_name: str
    grade: str

class StudentCreate(StudentBase):
    pass

class StudentInDB(StudentBase):
    id: PydanticObjectId = Field(alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )

class StudentOut(StudentBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={ObjectId: str}
    )

# User models
class UserBase(BaseModel):
    username: str
    email: str
    full_name: str
    role: str

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase):
    id: PydanticObjectId = Field(alias="_id")
    hashed_password: str
    disabled: bool = False

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )

class UserOut(BaseModel):
    username: str
    email: str
    full_name: str
    role: str
    disabled: bool = False

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={ObjectId: str}
    )
