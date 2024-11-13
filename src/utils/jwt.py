from datetime import datetime, timedelta
from typing import Dict, Any
from jose import jwt
from src.core.config import settings
import logging

logger = logging.getLogger(__name__)

def create_access_token(data: Dict[str, Any]) -> str:
    """创建访问令牌"""
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.JWT_SECRET_KEY, 
            algorithm=settings.JWT_ALGORITHM
        )
        return encoded_jwt
    except Exception as e:
        logger.error(f"Token creation error: {str(e)}")
        raise 