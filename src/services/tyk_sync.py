import httpx
import logging
from datetime import datetime
from typing import Optional
from src.core.config import settings
from src.models.user import UserInDB, TykStatus, UserUpdate, UserRole
from src.db.users import UserDB

logger = logging.getLogger(__name__)

class TykSyncService:
    def __init__(self):
        self.settings = settings
        self.headers = {
            "Authorization": self.settings.TYK_SECRET,
            "Content-Type": "application/json"
        }
        self.client = httpx.AsyncClient(
            timeout=30.0,
            verify=False,
            proxies=None,
            trust_env=False
        )
    
    async def sync_user_to_tyk(self, user: UserInDB) -> Optional[str]:
        """同步用户到Tyk"""
        try:
            # 根据用户角色选择策略
            policy_id = (
                self.settings.TYK_PREMIUM_POLICY_ID 
                if user.role == UserRole.PREMIUM 
                else self.settings.TYK_BASIC_POLICY_ID
            )
            
            key_data = {
                "alias": user.email,
                "org_id": self.settings.TYK_ORG_ID,
                "policies": [policy_id],
                "meta_data": {
                    "user_id": str(user.id),
                    "role": user.role.value
                }
            }
            
            response = await self.client.post(
                f"{self.settings.TYK_GATEWAY_URL}/tyk/keys",
                headers=self.headers,
                json=key_data
            )
            
            if response.status_code == 200:
                tyk_api_key = response.json().get("key")
                # 更新用户的Tyk状态
                await UserDB.update(user.email, UserUpdate(
                    tyk_api_key=tyk_api_key,
                    tyk_status=TykStatus.ACTIVE,
                    last_sync_time=datetime.utcnow()
                ))
                return tyk_api_key
            else:
                logger.error(f"Failed to sync user to Tyk: {response.text}")
                await UserDB.update(user.email, UserUpdate(
                    tyk_status=TykStatus.ERROR
                ))
                return None
                    
        except Exception as e:
            logger.error(f"Error syncing user to Tyk: {str(e)}")
            await UserDB.update(user.email, UserUpdate(
                tyk_status=TykStatus.ERROR
            ))
            return None
            
    async def revoke_tyk_access(self, user: UserInDB) -> bool:
        """撤销用户的Tyk访问权限"""
        try:
            if not user.tyk_api_key:
                return True
                
            response = await self.client.delete(
                f"{self.settings.TYK_GATEWAY_URL}/tyk/keys/{user.tyk_api_key}",
                headers=self.headers
            )
                
            if response.status_code in [200, 404]:
                await UserDB.update(user.email, UserUpdate(
                    tyk_api_key=None,
                    tyk_status=TykStatus.INACTIVE,
                    last_sync_time=datetime.utcnow()
                ))
                return True
                    
            logger.error(f"Failed to revoke Tyk access: {response.text}")
            return False
                
        except Exception as e:
            logger.error(f"Error revoking Tyk access: {str(e)}")
            return False 

    async def __del__(self):
        """清理资源"""
        if hasattr(self, 'client'):
            await self.client.aclose() 