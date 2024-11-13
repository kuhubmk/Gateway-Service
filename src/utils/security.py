import re
from passlib.context import CryptContext
import logging

logger = logging.getLogger(__name__)

# 密码加密上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password_strength(password: str) -> tuple[bool, str]:
    """验证密码强度
    返回: (是否通过, 错误信息)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
        
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter"
        
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
        
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
        
    return True, ""

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {str(e)}")
        return False

def get_password_hash(password: str) -> str:
    """获取密码哈希值"""
    try:
        # 先验证密码强度
        is_valid, error_msg = verify_password_strength(password)
        if not is_valid:
            raise ValueError(error_msg)
        return pwd_context.hash(password)
    except Exception as e:
        logger.error(f"Password hashing error: {str(e)}")
        raise 