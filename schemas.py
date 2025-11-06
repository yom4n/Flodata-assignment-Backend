from datetime import datetime
from typing import Optional, Union
from pydantic import BaseModel, Field, ConfigDict
from bson import ObjectId

# Custom Pydantic type for MongoDB ObjectId
class PydanticObjectId(str):
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        from pydantic_core import core_schema
        
        def validate(value: str) -> str:
            if not ObjectId.is_valid(value):
                raise ValueError('Invalid ObjectId')
            return str(value)
            
        return core_schema.no_info_plain_validator_function(
            function=validate,
            serialization=core_schema.to_string_ser_schema(),
        )
    
    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema, _handler):
        field_schema.update(type='string')
        return field_schema

# Token models
class TokenBase(BaseModel):
    token_type: str = "bearer"
    access_token: str
    # refresh_token: str
    
class Token(TokenBase):
    refresh_token: str
    
class TokenWithUser(TokenBase):
    user: 'UserOut'

class RefreshToken(BaseModel):
    refresh_token: str

class TokenData(BaseModel):
    username: str | None = None
    token_type: str | None = None

class TokenRequest(BaseModel):
    access_token: str = Field(..., description="The access token to validate and get user data")

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
    _id: str
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
