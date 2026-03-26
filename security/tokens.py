from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID
from config import ALGORITHM, SECRET_KEY, ACCESS_TOKEN_EXPIRE_HOURS, REFRESH_TOKEN_EXPIRE_DAYS
from jose import jwt, JWTError, ExpiredSignatureError
from secrets import token_urlsafe
from hashlib import sha256
from database.models import EmployeeModel, ManagerModel, EmployeeRefreshTokenModel, ManagerRefreshTokenModel
from fastapi import HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from database.initialization import get_db


def hash_refresh_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


async def create_tokens(user_id: UUID, role: str, db: AsyncSession) -> dict:
    """
    Creates access + refresh tokens and adds the refresh token record to the session.
    Does NOT commit — the caller owns the transaction.
    """
    expire = datetime.now(tz=timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode = {"sub": str(user_id), "role": role, "exp": expire}
    access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    refresh_token = token_urlsafe(64)
    token_hash = hash_refresh_token(refresh_token)
    refresh_expires = datetime.now(tz=timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    if role == "employee":
        db_refresh_token = EmployeeRefreshTokenModel(
            employee_id=user_id,
            token_hash=token_hash,
            expires_at=refresh_expires,
        )
    elif role == "manager":
        db_refresh_token = ManagerRefreshTokenModel(
            manager_id=user_id,
            token_hash=token_hash,
            expires_at=refresh_expires,
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid role")

    db.add(db_refresh_token)
    # NOTE: No commit here — callers commit after this returns.

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


security = HTTPBearer()


async def get_user_from_access_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = UUID(payload["sub"])
        role = payload["role"]
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    if role == "employee":
        result = await db.execute(select(EmployeeModel).where(EmployeeModel.id == user_id))
        user = result.scalar_one_or_none()
    elif role == "manager":
        result = await db.execute(select(ManagerModel).where(ManagerModel.id == user_id))
        user = result.scalar_one_or_none()
    else:
        raise HTTPException(status_code=401, detail="Invalid role in token")

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


async def get_current_employee(user=Depends(get_user_from_access_token)):
    if not isinstance(user, EmployeeModel):
        raise HTTPException(status_code=403, detail="Access forbidden: employees only")
    return user


async def get_current_manager(user=Depends(get_user_from_access_token)):
    if not isinstance(user, ManagerModel):
        raise HTTPException(status_code=403, detail="Access forbidden: managers only")
    return user