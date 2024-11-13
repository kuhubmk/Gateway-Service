from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, EmailStr
from datetime import datetime

class UserRole(str, Enum):
    BASIC = "BASIC"
    PREMIUM = "PREMIUM"
    ADMIN = "ADMIN"

class Permission(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    ADMIN = "ADMIN"

class TykStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    PENDING = "PENDING"
    ERROR = "ERROR"

class Feature(str, Enum):
    SPEECH_TO_TEXT = "SPEECH_TO_TEXT"
    TEXT_PROCESS = "TEXT_PROCESS"
    TEXT_TO_SPEECH = "TEXT_TO_SPEECH"
    IMAGE_GENERATE = "IMAGE_GENERATE"

class FeatureUsage(BaseModel):
    """功能使用记录"""
    feature_id: str
    daily_limit: int = 0
    monthly_limit: int = 0
    daily_used: int = 0
    monthly_used: int = 0
    last_used: Optional[datetime] = None

class PermissionUpdate(BaseModel):
    permission: Permission

class UserBase(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.BASIC
    is_active: bool = True
    permissions: List[Permission] = [Permission.READ]

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    permissions: Optional[List[Permission]] = None
    tyk_status: Optional[TykStatus] = None

class UserInDB(UserBase):
    id: int
    hashed_password: str
    created_at: datetime
    tyk_api_key: Optional[str] = None
    tyk_policy_id: Optional[str] = None
    tyk_status: TykStatus = TykStatus.PENDING
    last_sync_time: Optional[datetime] = None
    feature_usage: Dict[str, dict] = {}
    email_verified: bool = False
    email_verification_token: Optional[str] = None
    email_verification_expires: Optional[datetime] = None

class User(UserBase):
    id: int
    created_at: datetime
    tyk_status: TykStatus
    email_verified: bool = False
