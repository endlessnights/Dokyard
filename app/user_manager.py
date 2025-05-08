# app/user_manager.py
import logging

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from tortoise.exceptions import DoesNotExist

from app.models import User
from app.config import SECRET_KEY, ALGORITHM

logger = logging.getLogger(__name__)

# Точка авторизации для Swagger UI и для того, чтобы знать, куда POSTить логин
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


async def get_current_user_cli(token: str = Depends(oauth2_scheme)) -> User:
    logger.debug(f"[CLI-auth] raw token = {token!r}")
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # JWTError поймает любые проблемы при декодировании
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    try:
        user = await User.get(username=username).prefetch_related("groups")
    except DoesNotExist:
        raise credentials_exc

    return user


async def get_current_user(request: Request) -> User:
    token = request.cookies.get("access_token")
    if not token:
        logger.warning("Access token cookie not found")
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        # Split the token to remove the "Bearer " prefix
        scheme, token = token.split(" ")
        if scheme.lower() != "bearer":
            logger.warning(f"Invalid auth scheme: {scheme}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            logger.warning("Username not found in token payload")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Fetch the User instance from the database with groups
        user = await User.get(username=username).prefetch_related("groups")
        logger.info(f"Authenticated user: {user.username}")
        return user
    except (jwt.PyJWTError, ValueError) as e:
        logger.error(f"Error decoding JWT token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except DoesNotExist:
        logger.error(f"User not found: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )