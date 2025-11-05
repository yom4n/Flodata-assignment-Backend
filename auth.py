from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from motor.motor_asyncio import AsyncIOMotorClient

from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from . import database
from . import schemas

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate a password hash."""
    return pwd_context.hash(password)

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_db() -> AsyncIOMotorClient:
    """Dependency to get the database client."""
    return database.client

async def get_user(username: str) -> Optional[schemas.UserInDB]:
    """Get a user by username."""
    user_dict = await database.user_collection.find_one({"username": username})
    if user_dict:
        return schemas.UserInDB(**user_dict)
    return None

async def authenticate_user(username: str, password: str) -> Optional[schemas.UserOut]:
    """Authenticate a user with username and password."""
    user = await get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return schemas.UserOut(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        disabled=user.disabled
    )

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncIOMotorClient = Depends(get_db)
) -> schemas.UserOut:
    """Dependency to get the current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return schemas.UserOut(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        disabled=user.disabled
    )

async def get_current_admin(
    current_user: schemas.UserOut = Depends(get_current_user)
) -> schemas.UserOut:
    """Dependency to check if the current user is an admin."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

# Router for authentication endpoints
auth_router = APIRouter(tags=["Authentication"])

@auth_router.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: schemas.UserCreate):
    """Register a new user."""
    # Check if user already exists
    existing_user = await database.user_collection.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Hash the password
    hashed_password = get_password_hash(user_data.password)
    
    # Create user document
    user_dict = user_data.model_dump()
    user_dict["hashed_password"] = hashed_password
    user_dict.pop("password", None)  # Remove the plain password
    
    # Set default role if not provided
    if "role" not in user_dict or not user_dict["role"]:
        user_dict["role"] = "user"
    
    # Insert user into database
    result = await database.user_collection.insert_one(user_dict)
    
    # Return the created user (without password)
    created_user = await database.user_collection.find_one({"_id": result.inserted_id})
    return schemas.UserOut(**created_user)

@auth_router.post("/login", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """OAuth2 compatible token login, get an access token for future requests."""
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}
