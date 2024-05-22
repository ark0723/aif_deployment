import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from urllib.parse import unquote

load_dotenv()


# generate JWT token
def create_jwt_token(data: dict, expires_delta: timedelta) -> str:
    expiration = datetime.now() + expires_delta
    token_data = {"exp": expiration, **data}
    token = jwt.encode(token_data, os.getenv("SECRET_KEY"), algorithm="HS256")
    return token


# token verification and authentication
security = HTTPBearer()


def verify_jwt_token(token: str) -> dict:
    try:
        decoded_data = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        return decoded_data
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    except jwt.DecodeError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Error decoding token"
        )


async def get_current_user(token: HTTPAuthorizationCredentials = Depends(security)):
    if not token.scheme == "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme",
        )
    # Replace %20 with spaces and then decode the token
    token_value = unquote(token.credentials)
    user_data = verify_jwt_token(token_value)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    return user_data
