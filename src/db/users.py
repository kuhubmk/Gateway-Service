from typing import Optional, List
import logging
from src.models.user import UserCreate, UserInDB, UserRole, UserUpdate, Permission, TykStatus, Feature, FeatureUsage
from src.core.config import settings
from src.utils.security import get_password_hash
from fastapi import HTTPException
from src.db.turso import TursoClient
import json
from datetime import datetime, timedelta
import secrets
from src.db.monitoring import monitor_db_operation

logger = logging.getLogger(__name__)

class UserDB:
    """用户数据库操作类"""
    
    @classmethod
    async def init_db(cls):
        """初始化数据库"""
        try:
            # 删除现有表（如果存在）
            await TursoClient.execute('DROP TABLE IF EXISTS feature_usage')
            await TursoClient.execute('DROP TABLE IF EXISTS users')
            
            # 创建用户表
            await TursoClient.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'BASIC',
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    tyk_api_key TEXT,
                    tyk_policy_id TEXT,
                    tyk_status TEXT DEFAULT 'PENDING',
                    last_sync_time TIMESTAMP,
                    permissions TEXT DEFAULT '["READ"]',
                    feature_usage TEXT DEFAULT '{}',
                    reset_token TEXT,
                    reset_token_expires TIMESTAMP,
                    email_verified BOOLEAN DEFAULT FALSE,
                    email_verification_token TEXT,
                    email_verification_expires TIMESTAMP
                )
            ''')

            # 创建功能使用记录表
            await TursoClient.execute('''
                CREATE TABLE feature_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    feature_id TEXT NOT NULL,
                    daily_limit INTEGER DEFAULT 0,
                    monthly_limit INTEGER DEFAULT 0,
                    daily_used INTEGER DEFAULT 0,
                    monthly_used INTEGER DEFAULT 0,
                    last_used TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    UNIQUE(user_id, feature_id)
                )
            ''')
            
            # 创建管理员用户
            admin_exists = await cls.get_by_email(settings.ADMIN_EMAIL)
            if not admin_exists:
                await cls.create(UserCreate(
                    email=settings.ADMIN_EMAIL,
                    password=settings.ADMIN_PASSWORD,
                    role=UserRole.ADMIN,
                    permissions=[Permission.ADMIN]
                ))
                
            logger.info("Database tables initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            raise

    @classmethod
    @monitor_db_operation("get_by_email")
    async def get_by_email(cls, email: str) -> Optional[UserInDB]:
        """通过邮箱获取用户"""
        try:
            result = await TursoClient.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            )
            if result and result.rows:
                row_dict = dict(zip(result.columns, result.rows[0]))
                # 处理 JSON 字段
                if "permissions" in row_dict:
                    row_dict["permissions"] = [
                        Permission(p) for p in json.loads(row_dict["permissions"])
                    ]
                if "tyk_status" in row_dict:
                    row_dict["tyk_status"] = TykStatus(row_dict["tyk_status"])
                if "created_at" in row_dict:
                    row_dict["created_at"] = datetime.fromisoformat(row_dict["created_at"])
                if "feature_usage" in row_dict:
                    # 确保 feature_usage 是有效的 JSON 字符串
                    try:
                        row_dict["feature_usage"] = json.loads(row_dict["feature_usage"])
                    except:
                        row_dict["feature_usage"] = {}
                return UserInDB(**row_dict)
            return None
        except Exception as e:
            logger.error(f"Error getting user by email: {str(e)}")
            raise

    @classmethod
    @monitor_db_operation("create_user")
    async def create(cls, user: UserCreate) -> Optional[UserInDB]:
        """创建新用户"""
        try:
            # 检查邮箱是否已存在
            existing_user = await cls.get_by_email(user.email)
            if existing_user:
                logger.warning(f"Attempt to create user with existing email: {user.email}")
                return existing_user  # 如果用户已存在，直接返回现有用户
            
            hashed_password = get_password_hash(user.password)
            
            # 使用 Turso 客户端创建用户
            await TursoClient.execute(
                """
                INSERT INTO users (
                    email, 
                    hashed_password, 
                    role, 
                    is_active, 
                    permissions,
                    tyk_status,
                    feature_usage
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user.email,
                    hashed_password,
                    user.role.value,
                    True,
                    json.dumps([p.value for p in user.permissions]),
                    TykStatus.PENDING.value,
                    json.dumps({})  # 初始化空的 feature_usage 字典
                )
            )
            
            # 获取创建的用户
            created_user = await cls.get_by_email(user.email)
            if not created_user:
                raise Exception("Failed to retrieve created user")
                
            logger.info(f"Successfully created user: {user.email}")
            return created_user
                
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            if "UNIQUE constraint" in str(e):
                raise HTTPException(
                    status_code=400,
                    detail="Email already exists"
                )
            raise

    @classmethod
    @monitor_db_operation("update_user")
    async def update(cls, email: str, user_update: UserUpdate) -> Optional[UserInDB]:
        """更新用户信息"""
        try:
            updates = []
            values = []
            
            if user_update.email:
                updates.append("email = ?")
                values.append(user_update.email)
                
            if user_update.password:
                updates.append("hashed_password = ?")
                values.append(get_password_hash(user_update.password))
                
            if user_update.role:
                updates.append("role = ?")
                values.append(user_update.role.value)
                
            if user_update.is_active is not None:
                updates.append("is_active = ?")
                values.append(user_update.is_active)
                
            if user_update.permissions:
                updates.append("permissions = ?")
                values.append(json.dumps([p.value for p in user_update.permissions]))
                
            if user_update.tyk_status:
                updates.append("tyk_status = ?")
                values.append(user_update.tyk_status.value)
                
            if updates:
                values.append(email)
                query = f"UPDATE users SET {', '.join(updates)} WHERE email = ?"
                await TursoClient.execute(query, tuple(values))
                
            # 获取更新后的用户
            updated_user = await cls.get_by_email(email)
            if not updated_user:
                raise HTTPException(
                    status_code=404,
                    detail="User not found"
                )
                
            return updated_user
            
        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            raise

    @classmethod
    @monitor_db_operation("get_all_users")
    async def get_all_users(cls) -> List[UserInDB]:
        """获取所有用户"""
        try:
            result = await TursoClient.execute("SELECT * FROM users")
            users = []
            for row in result.rows:
                row_dict = dict(zip(result.columns, row))
                # 处理 JSON 字段
                if "permissions" in row_dict:
                    row_dict["permissions"] = [
                        Permission(p) for p in json.loads(row_dict["permissions"])
                    ]
                if "tyk_status" in row_dict:
                    row_dict["tyk_status"] = TykStatus(row_dict["tyk_status"])
                if "created_at" in row_dict:
                    row_dict["created_at"] = datetime.fromisoformat(row_dict["created_at"])
                if "feature_usage" in row_dict:
                    try:
                        row_dict["feature_usage"] = json.loads(row_dict["feature_usage"])
                    except:
                        row_dict["feature_usage"] = {}
                users.append(UserInDB(**row_dict))
            return users
        except Exception as e:
            logger.error(f"Error getting all users: {str(e)}")
            raise

    @classmethod
    async def delete_test_users(cls):
        """删除测试用户数据"""
        try:
            await TursoClient.execute(
                "DELETE FROM users WHERE email LIKE '%@example.com'"
            )
            logger.info("Successfully cleaned up test users")
        except Exception as e:
            logger.error(f"Error deleting test users: {str(e)}")
            raise

    @classmethod
    async def update_feature_usage(cls, user_id: int, feature_id: str, increment: int = 1):
        """更新功能使用记录"""
        try:
            now = datetime.utcnow()
            today = now.date()
            
            # 获取当前使用记录
            result = await TursoClient.execute(
                """
                SELECT * FROM feature_usage 
                WHERE user_id = ? AND feature_id = ?
                """,
                (user_id, feature_id)
            )
            
            if not result.rows:
                # 创建新记录
                await TursoClient.execute(
                    """
                    INSERT INTO feature_usage (
                        user_id, feature_id, daily_used, monthly_used, last_used
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, feature_id, increment, increment, now)
                )
            else:
                last_used = datetime.fromisoformat(dict(zip(result.columns, result.rows[0]))['last_used'])
                
                # 检查是否需要重置计数
                if last_used.date() < today:
                    daily_used = increment
                else:
                    daily_used = dict(zip(result.columns, result.rows[0]))['daily_used'] + increment
                    
                if last_used.month < now.month:
                    monthly_used = increment
                else:
                    monthly_used = dict(zip(result.columns, result.rows[0]))['monthly_used'] + increment
                
                # 更新记录
                await TursoClient.execute(
                    """
                    UPDATE feature_usage 
                    SET daily_used = ?, monthly_used = ?, last_used = ?
                    WHERE user_id = ? AND feature_id = ?
                    """,
                    (daily_used, monthly_used, now, user_id, feature_id)
                )
                
            return True
        except Exception as e:
            logger.error(f"Error updating feature usage: {str(e)}")
            raise

    @classmethod
    async def get_feature_usage(cls, user_id: int, feature_id: str) -> Optional[FeatureUsage]:
        """获取功能使用记录"""
        try:
            result = await TursoClient.execute(
                """
                SELECT * FROM feature_usage 
                WHERE user_id = ? AND feature_id = ?
                """,
                (user_id, feature_id)
            )
            
            if result and result.rows:
                row_dict = dict(zip(result.columns, result.rows[0]))
                return FeatureUsage(**row_dict)
            return None
        except Exception as e:
            logger.error(f"Error getting feature usage: {str(e)}")
            raise

    @classmethod
    async def check_feature_limit(cls, user_id: int, feature_id: str) -> bool:
        """检查功能使用是否超出限制"""
        try:
            # 获取用户信息
            user = await cls.get_by_id(user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # 获取功能使用记录
            usage = await cls.get_feature_usage(user_id, feature_id)
            if not usage:
                return True  # 没有使用记录，说明未超限
            
            # 获取限制配置
            limits = settings.FEATURE_LIMITS[feature_id][user.role.value]
            
            # 检查是否超出限制
            if limits.get("daily_limit") != -1 and usage.daily_used >= limits["daily_limit"]:
                raise HTTPException(
                    status_code=429,
                    detail=f"Daily limit exceeded for {feature_id}"
                )
            
            if limits.get("monthly_limit") and usage.monthly_used >= limits["monthly_limit"]:
                raise HTTPException(
                    status_code=429,
                    detail=f"Monthly limit exceeded for {feature_id}"
                )
            
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error checking feature limit: {str(e)}")
            raise

    @classmethod
    async def init_feature_limits(cls, user_id: int, role: UserRole):
        """初始化用户的功能限制"""
        try:
            for feature_id in Feature:
                limits = settings.FEATURE_LIMITS[feature_id.value][role.value]
                await TursoClient.execute(
                    """
                    INSERT INTO feature_usage (
                        user_id, 
                        feature_id, 
                        daily_limit,
                        monthly_limit
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT (user_id, feature_id) 
                    DO UPDATE SET 
                        daily_limit = ?,
                        monthly_limit = ?
                    """,
                    (
                        user_id, 
                        feature_id.value, 
                        limits["daily"],
                        limits["monthly"],
                        limits["daily"],
                        limits["monthly"]
                    )
                )
        except Exception as e:
            logger.error(f"Error initializing feature limits: {str(e)}")
            raise

    @classmethod
    async def get_by_id(cls, user_id: int) -> Optional[UserInDB]:
        """通过ID获取用户"""
        try:
            result = await TursoClient.execute(
                "SELECT * FROM users WHERE id = ?",
                (user_id,)
            )
            if result and result.rows:
                row_dict = dict(zip(result.columns, result.rows[0]))
                # 处理 JSON 字段
                if "permissions" in row_dict:
                    row_dict["permissions"] = [
                        Permission(p) for p in json.loads(row_dict["permissions"])
                    ]
                if "tyk_status" in row_dict:
                    row_dict["tyk_status"] = TykStatus(row_dict["tyk_status"])
                if "created_at" in row_dict:
                    row_dict["created_at"] = datetime.fromisoformat(row_dict["created_at"])
                if "feature_usage" in row_dict:
                    try:
                        row_dict["feature_usage"] = json.loads(row_dict["feature_usage"])
                    except:
                        row_dict["feature_usage"] = {}
                return UserInDB(**row_dict)
            return None
        except Exception as e:
            logger.error(f"Error getting user by id: {str(e)}")
            raise

    @classmethod
    async def create_session(cls, user_id: int, token: str):
        """创建用户会话"""
        pass

    @classmethod
    async def invalidate_session(cls, token: str):
        """使会话失效"""
        pass

    @classmethod
    async def create_reset_token(cls, email: str) -> Optional[str]:
        """创建密码重置令牌"""
        try:
            # 检查用户是否存在
            user = await cls.get_by_email(email)
            if not user:
                logger.warning(f"Attempt to reset password for non-existent email: {email}")
                return None
            
            # 生成重置令牌
            reset_token = secrets.token_urlsafe(32)
            reset_expires = datetime.utcnow() + timedelta(hours=24)
            
            # 存储重置令牌
            await TursoClient.execute(
                """
                UPDATE users 
                SET reset_token = ?, 
                    reset_token_expires = ?
                WHERE email = ?
                """,
                (reset_token, reset_expires.isoformat(), email)  # 确保日期格式正确
            )
            
            logger.info(f"Reset token created for user: {email}")
            return reset_token
            
        except Exception as e:
            logger.error(f"Error creating reset token: {str(e)}")
            # 返回 None 而不是抛出异常
            return None

    @classmethod
    async def verify_reset_token(cls, token: str) -> Optional[str]:
        """验证重置令牌"""
        try:
            result = await TursoClient.execute(
                """
                SELECT email, reset_token_expires 
                FROM users 
                WHERE reset_token = ?
                """,
                (token,)
            )
            
            if not result.rows:
                return None
            
            row = dict(zip(result.columns, result.rows[0]))
            expires = datetime.fromisoformat(row['reset_token_expires'])
            
            if expires < datetime.utcnow():
                return None
            
            return row['email']
        except Exception as e:
            logger.error(f"Error verifying reset token: {str(e)}")
            raise

    @classmethod
    async def reset_password(cls, token: str, new_password: str) -> bool:
        """重置密码"""
        try:
            # 验证令牌
            email = await cls.verify_reset_token(token)
            if not email:
                return False
            
            # 更新密码
            hashed_password = get_password_hash(new_password)
            await TursoClient.execute(
                """
                UPDATE users 
                SET hashed_password = ?,
                    reset_token = NULL,
                    reset_token_expires = NULL
                WHERE email = ?
                """,
                (hashed_password, email)
            )
            
            return True
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            raise

    @classmethod
    async def create_verification_token(cls, email: str) -> str:
        """创建邮箱验证令牌"""
        try:
            token = secrets.token_urlsafe(32)
            expires = datetime.utcnow() + timedelta(hours=24)
            
            await TursoClient.execute(
                """
                UPDATE users 
                SET email_verification_token = ?,
                    email_verification_expires = ?
                WHERE email = ?
                """,
                (token, expires, email)
            )
            
            return token
        except Exception as e:
            logger.error(f"Error creating verification token: {str(e)}")
            raise

    @classmethod
    async def verify_email(cls, token: str) -> bool:
        """验证邮箱"""
        try:
            result = await TursoClient.execute(
                """
                SELECT email, email_verification_expires 
                FROM users 
                WHERE email_verification_token = ?
                """,
                (token,)
            )
            
            if not result.rows:
                return False
            
            row = dict(zip(result.columns, result.rows[0]))
            expires = datetime.fromisoformat(row['email_verification_expires'])
            
            if expires < datetime.utcnow():
                return False
            
            # 更新验证状态
            await TursoClient.execute(
                """
                UPDATE users 
                SET email_verified = TRUE,
                    email_verification_token = NULL,
                    email_verification_expires = NULL
                WHERE email_verification_token = ?
                """,
                (token,)
            )
            
            return True
        except Exception as e:
            logger.error(f"Error verifying email: {str(e)}")
            raise

    @classmethod
    @monitor_db_operation("get_user_stats")
    async def get_user_stats(cls) -> dict:
        """获取用户统计信息"""
        try:
            # 获取总用户数
            total_result = await TursoClient.execute(
                "SELECT COUNT(*) as total FROM users"
            )
            total_users = dict(zip(total_result.columns, total_result.rows[0]))['total']

            # 获取今日新增用户数
            today = datetime.utcnow().date()
            new_users_result = await TursoClient.execute(
                """
                SELECT COUNT(*) as new_users 
                FROM users 
                WHERE DATE(created_at) = DATE(?)
                """,
                (today.isoformat(),)
            )
            new_users = dict(zip(new_users_result.columns, new_users_result.rows[0]))['new_users']

            # 获取活跃用户数（最近7天有登录记录的用户）
            active_users_result = await TursoClient.execute(
                """
                SELECT COUNT(DISTINCT user_id) as active_users 
                FROM feature_usage 
                WHERE last_used >= datetime('now', '-7 days')
                """
            )
            active_users = dict(zip(active_users_result.columns, active_users_result.rows[0]))['active_users']

            # 获取各角色用户数量
            role_stats_result = await TursoClient.execute(
                """
                SELECT role, COUNT(*) as count 
                FROM users 
                GROUP BY role
                """
            )
            role_stats = {
                row[0]: row[1] 
                for row in role_stats_result.rows
            }

            return {
                "total_users": total_users,
                "new_users_today": new_users,
                "active_users_7d": active_users,
                "role_distribution": role_stats,
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Error getting user stats: {str(e)}")
            raise

# 初始化数据库
import os
if not os.path.exists('data'):
    os.makedirs('data')