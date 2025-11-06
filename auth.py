from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
import jwt
from jwt import PyJWTError, ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext
from fastapi import APIRouter, Depends, HTTPException, status, Form, Response, Request, Body
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from motor.motor_asyncio import AsyncIOMotorClient

from config import (
    SECRET_KEY, 
    ALGORITHM, 
    ACCESS_TOKEN_EXPIRE_MINUTES, 
    REFRESH_TOKEN_EXPIRE_DAYS,
    DATABASE_NAME
)
import database
import schemas

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate a password hash."""
    return pwd_context.hash(password)

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

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

def create_token(
    data: Dict[str, Any], 
    token_type: str = "access",
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT token (access or refresh)."""
    to_encode = data.copy()
    
    # Set expiration time
    if token_type == "refresh":
        if not expires_delta:
            expires_delta = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"type": "refresh"})
    else:  # access token
        if not expires_delta:
            expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"type": "access"})
    
    expire = datetime.utcnow() + expires_delta
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
    })
    
    # PyJWT's encode returns a string (not bytes) by default
    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return encoded_jwt

# Alias for backward compatibility
create_access_token = create_token

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
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_aud": False}  # Skip audience verification
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (PyJWTError, InvalidTokenError):
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


@auth_router.post("/me", response_model=schemas.UserOut)
async def get_current_user_from_token(
    token_data: schemas.TokenRequest = Body(...),
    db: AsyncIOMotorClient = Depends(get_db)
) -> schemas.UserOut:
    """
    Get current user data using an access token.
    The access token should be provided in the request body.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode the token
        payload = jwt.decode(
            token_data.access_token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_signature": True}
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except (PyJWTError, ExpiredSignatureError, InvalidTokenError):
        raise credentials_exception
    
    # Get user from database using email (username)
    user = await db[DATABASE_NAME].users.find_one({"username": username})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Convert MongoDB document to UserOut model
    return schemas.UserOut(**user)

@auth_router.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: schemas.UserCreate):
    """Register a new user."""

    ALLOWED_ROLES = {"admin", "user"}

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
    
    print(user_dict)
    # Set default role if not provided
    if user_dict.get("role") not in ALLOWED_ROLES:
        user_dict["role"] = "user"
    
    # Insert user into database
    result = await database.user_collection.insert_one(user_dict)
    
    # Return the created user (without password)
    created_user = await database.user_collection.find_one({"_id": result.inserted_id})
    return schemas.UserOut(**created_user)

@auth_router.post("/login", response_model=schemas.TokenWithUser)
async def login_for_access_token(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    OAuth2 compatible token login.
    - Returns access token and user details in response body
    - Sets refresh token in HTTP-only cookie
    """
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create tokens
    access_token = create_token(
        data={"sub": user.email},
        token_type="access"
    )
    
    refresh_token = create_token(
        data={"sub": user.username},
        token_type="refresh"
    )
    
    # Store refresh token in database
    await database.client[DATABASE_NAME]["refresh_tokens"].insert_one({
        "user_id": user.username,
        "token": refresh_token,
        "expires_at": datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        "created_at": datetime.utcnow()
    })
    
    # Set refresh token in HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,  # in seconds
        samesite="lax",
        secure=True,  # Set to True in production with HTTPS
        path="/api/v1/auth/refresh"  # Only send for refresh requests
    )
    
    # Convert user to UserOut model to exclude sensitive data
    user_out = schemas.UserOut(**user.dict())
    
    # Return the access token, token type, and user details
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_out.dict()
    }

@auth_router.post("/refresh", response_model=schemas.TokenBase)
async def refresh_access_token(
    request: Request,
    response: Response,
):
    """
    Get a new access token using a refresh token from HTTP-only cookie.
    The refresh token should be stored in an HTTP-only cookie named 'refresh_token'.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Get refresh token from HTTP-only cookie
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is missing",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Verify refresh token
        payload = jwt.decode(
            refresh_token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        
        # Check token type
        if payload.get("type") != "refresh":
            raise credentials_exception
            
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
            
        # Verify token is not revoked
        token_valid = await database.client[DATABASE_NAME]["refresh_tokens"].find_one({
            "token": refresh_token,
            "user_id": username,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        if not token_valid:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    # Create new access token
    access_token = create_token(
        data={"sub": username},
        token_type="access"
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@auth_router.post("/logout")
async def logout(
    refresh_data: schemas.RefreshToken,
    current_user: schemas.UserOut = Depends(get_current_user)
):
    """Revoke a refresh token."""
    # Remove the refresh token from the database
    result = await database.client[DATABASE_NAME]["refresh_tokens"].delete_one({
        "token": refresh_data.refresh_token,
        "user_id": current_user.username
    })
    
    return {"message": "Successfully logged out"}
