# api/auth.py
"""
Authentication and authorization module for DDoS Defense System
"""

import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import jwt
from pydantic import BaseModel
import secrets

# -------------------------------------------------
# Security
# -------------------------------------------------
security = HTTPBearer()

try:
    pwd_context = CryptContext(
        schemes=["bcrypt"],
        deprecated="auto",
        bcrypt__rounds=12,
        bcrypt__ident="2b",
        bcrypt__default_ident="2b"
    )
except Exception as e:
    # Fallback to simpler configuration if bcrypt has issues
    pwd_context = CryptContext(
        schemes=["bcrypt"],
        deprecated="auto",
        bcrypt__rounds=12
    )

# -------------------------------------------------
# JWT Configuration
# -------------------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# -------------------------------------------------
# Models
# -------------------------------------------------
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "viewer"
    disabled: bool = False


class Token(BaseModel):
    access_token: str
    token_type: str
    user: Dict[str, Any]


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


# -------------------------------------------------
# Mock user database (PRE-HASHED PASSWORDS)
# Passwords:
# admin123 | user123 | viewer123
# -------------------------------------------------
users_db: Dict[str, Dict[str, Any]] = {
    "admin": {
        "username": "admin",
        "full_name": "Administrator",
        "email": "admin@ddosdefense.local",
        "hashed_password": "$2b$12$Eh5/oI5/TmECmmxTVGFCgOQyXlhdELsUd8XxpdIx.DXkp/YLi/nF2",
        "role": "admin",
        "disabled": False,
    },
    "user": {
        "username": "user",
        "full_name": "Regular User",
        "email": "user@ddosdefense.local",
        "hashed_password": "$2b$12$YbteDuOYRJPXGBgRGqCc0ej9y2vbBkna5SmkhYEqswigDjOOEDne6",
        "role": "user",
        "disabled": False,
    },
    "viewer": {
        "username": "viewer",
        "full_name": "View Only",
        "email": "viewer@ddosdefense.local",
        "hashed_password": "$2b$12$Qu6pwM0tOaRhcpZJXA7qh.zHgP/F.uZkmXs5el09P.fGANMaubaIe",
        "role": "viewer",
        "disabled": False,
    },
}

# -------------------------------------------------
# Password helpers
# -------------------------------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Truncate password to 72 bytes as required by bcrypt
    plain_password = plain_password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    # Truncate password to 72 bytes as required by bcrypt
    password = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
    return pwd_context.hash(password)


# -------------------------------------------------
# Authentication helpers
# -------------------------------------------------
def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = users_db.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# -------------------------------------------------
# Token verification
# -------------------------------------------------
async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> TokenData:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role", "viewer")

        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )

        return TokenData(username=username, role=role)

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


# -------------------------------------------------
# User dependencies
# -------------------------------------------------
async def get_current_user(
    token_data: TokenData = Depends(verify_token),
) -> User:
    user_data = users_db.get(token_data.username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    return User(**user_data)


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_role(required_role: str):
    async def role_checker(
        current_user: User = Depends(get_current_active_user),
    ):
        if current_user.role not in (required_role, "admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions (required: {required_role})",
            )
        return current_user

    return role_checker


# Role shortcuts
require_admin = require_role("admin")
require_user = require_role("user")
require_viewer = require_role("viewer")


# -------------------------------------------------
# Utility helpers
# -------------------------------------------------
def create_user(
    username: str,
    password: str,
    email: str = None,
    full_name: str = None,
    role: str = "viewer",
) -> bool:
    if username in users_db:
        return False

    users_db[username] = {
        "username": username,
        "email": email or f"{username}@ddosdefense.local",
        "full_name": full_name or username.title(),
        "hashed_password": hash_password(password),
        "role": role if role in {"admin", "user", "viewer"} else "viewer",
        "disabled": False,
    }
    return True


def get_user_by_username(username: str) -> Optional[User]:
    data = users_db.get(username)
    return User(**data) if data else None


def list_users() -> List[User]:
    return [User(**data) for data in users_db.values()]
