from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from typing import List
from pydantic import BaseModel, EmailStr
from datetime import timedelta
import logging
from src.utils.security import verify_password, verify_password_strength
from src.utils.email import send_reset_password_email, send_verification_email
from src.utils.jwt import create_access_token
from src.models.user import (
    User, 
    UserCreate, 
    UserUpdate, 
    UserInDB, 
    Permission, 
    PermissionUpdate,
    UserRole,
    Feature
)
from src.core.config import settings
from src.utils.auth import get_current_active_user
from src.db.users import UserDB
from src.services.tyk_sync import TykSyncService
import json
from fastapi.responses import JSONResponse
import secrets
from src.utils.security import get_password_hash

router = APIRouter(tags=["authentication"])

logger = logging.getLogger(__name__)

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class LoginData(BaseModel):
    """登录数据模型"""
    email: EmailStr
    password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str

@router.post("/register", response_model=User)
async def register_user(user: UserCreate):
    """注册新用户"""
    try:
        # 检查邮箱是否已存在
        existing_user = await UserDB.get_by_email(user.email)
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Email already registered"
            )
            
        # 验证密码强度
        is_valid, error_msg = verify_password_strength(user.password)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=error_msg
            )
            
        # 创建新用户
        new_user = await UserDB.create(user)
        if not new_user:
            raise HTTPException(
                status_code=500,
                detail="Failed to create user"
            )
            
        # 同步到Tyk
        tyk_service = TykSyncService()
        tyk_api_key = await tyk_service.sync_user_to_tyk(new_user)
        if not tyk_api_key:
            logger.warning(f"Failed to sync user {new_user.email} to Tyk")
            
        # 移除敏感信息
        user_data = new_user.dict()
        user_data.pop("hashed_password", None)
        return user_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.post("/login", response_model=Token)
async def login(login_data: LoginData):
    """用户登录"""
    try:
        user = await UserDB.get_by_email(login_data.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
            
        if not verify_password(login_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
            
        # 创建访问令牌
        access_token = create_access_token({
            "sub": user.email,
            "role": user.role.value,
            "permissions": [p.value for p in user.permissions]
        })
        
        # 移除敏感信息
        user_dict = user.dict()
        user_dict.pop("hashed_password", None)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_dict
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """获取当前用户信息"""
    try:
        user = await UserDB.get_by_email(current_user.email)
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        user_dict = user.dict()
        user_dict.pop("hashed_password", None)
        return user_dict
    except Exception as e:
        logger.error(f"Error getting current user info: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.get("/users", response_model=List[User])
async def get_users(current_user: User = Depends(get_current_active_user)):
    """获取所有用户列表(仅管理员)"""
    try:
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=403,
                detail="Not enough permissions"
            )
            
        users = await UserDB.get_all_users()
        return [
            {
                **user.dict(exclude={"hashed_password"}),
                "feature_usage": json.loads(user.feature_usage) if isinstance(user.feature_usage, str) else user.feature_usage
            }
            for user in users
        ]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting users list: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.put("/users/{email}", response_model=User)
async def update_user(
    email: EmailStr,
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user)
):
    """更新用户信息"""
    try:
        if current_user.email != email and current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=403,
                detail="Not enough permissions"
            )
        
        updated_user = await UserDB.update(email, user_update)
        if not updated_user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
            
        user_dict = updated_user.dict()
        user_dict.pop("hashed_password", None)
        return user_dict
        
    except HTTPException as e:
        raise
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.post("/users/{email}/permissions", response_model=User)
async def add_user_permission(
    email: EmailStr,
    permission: PermissionUpdate,
    current_user: User = Depends(get_current_active_user)
):
    """添加用户权限"""
    try:
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=403,
                detail="Not enough permissions"
            )
        
        user = await UserDB.get_by_email(email)
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )
        
        # 修改默认权限列表
        current_permissions = getattr(user, 'permissions', [Permission.READ])
        if permission.permission not in current_permissions:
            current_permissions.append(permission.permission)
            
        # 更新用户
        user_update = UserUpdate(permissions=current_permissions)
        updated_user = await UserDB.update(email, user_update)
        if not updated_user:
            raise HTTPException(
                status_code=500,
                detail="Failed to update user permissions"
            )
            
        user_dict = updated_user.dict()
        user_dict.pop("hashed_password", None)
        return user_dict
        
    except HTTPException as e:
        raise
    except Exception as e:
        logger.error(f"Error updating user permissions: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
@router.post("/cleanup_test_data")
async def cleanup_test_data(request: Request):
    """清理测试数据的接口"""
    test_key = request.headers.get("X-Test-Key")
    if test_key != settings.TEST_KEY:
        raise HTTPException(status_code=401)
        
    try:
        # 清理测试用户数据
        await UserDB.delete_test_users()
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error cleaning up test data: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/users/{email}/status")
async def update_user_status(
    email: EmailStr,
    is_active: bool,
    current_user: User = Depends(get_current_active_user)
):
    """更新用户状态"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not enough permissions")
        
    try:
        user = await UserDB.get_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        tyk_service = TykSyncService()
        if is_active:
            await tyk_service.sync_user_to_tyk(user)
        else:
            await tyk_service.revoke_tyk_access(user)
            
        return {"status": "success"}
        
    except Exception as e:
        logger.error(f"Error updating user status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/feature/{feature_id}/use")
async def use_feature(
    feature_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """记录功能使用（仅用于统计）"""
    try:
        # 检查功能是否存在
        if feature_id not in [f.value for f in Feature]:
            raise HTTPException(
                status_code=400,
                detail="Invalid feature ID"
            )
        
        # 更新使用记录（仅用于统计）
        await UserDB.update_feature_usage(current_user.id, feature_id)
        
        # 获取最新使用情况
        usage = await UserDB.get_feature_usage(current_user.id, feature_id)
        
        return {
            "status": "success",
            "usage": usage
        }
        
    except Exception as e:
        logger.error(f"Error recording feature usage: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.get("/feature/{feature_id}/usage")
async def get_feature_usage(
    feature_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """获取功能使用情况"""
    try:
        usage = await UserDB.get_feature_usage(current_user.id, feature_id)
        if not usage:
            return {
                "daily_used": 0,
                "monthly_used": 0,
                "limits": settings.FEATURE_LIMITS[feature_id][current_user.role.value]
            }
            
        return {
            "daily_used": usage.daily_used,
            "monthly_used": usage.monthly_used,
            "limits": settings.FEATURE_LIMITS[feature_id][current_user.role.value]
        }
        
    except Exception as e:
        logger.error(f"Error getting feature usage: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.post("/request-password-reset")
async def request_password_reset(request: PasswordResetRequest):
    """请求密码重置"""
    try:
        # 检查用户是否存在
        user = await UserDB.get_by_email(request.email)
        if not user:
            return {"message": "If the email exists, a reset link will be sent"}
            
        # 生成重置链接并发送邮件
        reset_token = secrets.token_urlsafe(32)
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        
        # 发送邮件
        await send_reset_password_email(request.email, reset_token)
        
        return {"message": "Password reset email sent"}
        
    except Exception as e:
        logger.error(f"Error in password reset: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error processing password reset request"
        )

@router.post("/reset-password")
async def reset_password(reset_data: PasswordReset):
    """重置密码"""
    try:
        # 验证密码强度
        is_valid, error_msg = verify_password_strength(reset_data.new_password)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=error_msg
            )
            
        # 更新密码
        success = await UserDB.reset_password(
            reset_data.token,
            reset_data.new_password
        )
        
        if not success:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired reset token"
            )
            
        return {"message": "Password reset successful"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting password: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error resetting password"
        )

@router.get("/stats")
async def get_user_stats(current_user: User = Depends(get_current_active_user)):
    """获取用户统计信息（仅管理员）"""
    try:
        # 检查权限
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=403,
                detail="Not enough permissions"
            )
            
        # 获取统计信息
        stats = await UserDB.get_user_stats()
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error getting user statistics"
        )
