import pytest
import aiohttp
import asyncio
from datetime import datetime

BASE_URL = "http://localhost:8000"

class TestAuthService:
    @pytest.mark.asyncio
    async def test_user_registration_and_login(self):
        """测试用户注册和登录"""
        async with aiohttp.ClientSession() as session:
            # 1. 测试重复注册
            basic_user = {
                "email": "519501877@qq.com",
                "password": "Basic123!@#",
                "role": "BASIC"
            }
            
            # 第一次注册应该成功
            response = await session.post(
                f"{BASE_URL}/api/auth/register",
                json=basic_user
            )
            assert response.status == 200
            data = await response.json()
            assert data["role"] == "BASIC"
            print("✓ 用户首次注册成功")

            # 第二次注册应该失败
            response = await session.post(
                f"{BASE_URL}/api/auth/register",
                json=basic_user
            )
            assert response.status == 400  # 应该返回400错误
            data = await response.json()
            assert "detail" in data
            assert "already registered" in data["detail"]
            print("✓ 重复注册检测成功")

            # 2. 测试登录
            response = await session.post(
                f"{BASE_URL}/api/auth/login",
                json={
                    "email": basic_user["email"],
                    "password": basic_user["password"]
                }
            )
            assert response.status == 200
            data = await response.json()
            assert "access_token" in data
            token = data["access_token"]
            print("✓ 用户登录成功")

            return token

    @pytest.mark.asyncio
    async def test_password_reset(self):
        """测试密码重置流程"""
        async with aiohttp.ClientSession() as session:
            # 1. 请求密码重置
            response = await session.post(
                f"{BASE_URL}/api/auth/request-password-reset",
                json={"email": "519501877@qq.com"}
            )
            assert response.status == 200
            print("✓ 密码重置邮件已发送")

    @pytest.mark.asyncio
    async def test_feature_usage(self, token):
        """测试功能使用统计"""
        async with aiohttp.ClientSession() as session:
            headers = {"Authorization": f"Bearer {token}"}
            
            # 测试所有功能
            features = ["SPEECH_TO_TEXT", "TEXT_PROCESS", "TEXT_TO_SPEECH", "IMAGE_GENERATE"]
            for feature in features:
                # 记录使用
                response = await session.post(
                    f"{BASE_URL}/api/auth/feature/{feature}/use",
                    headers=headers
                )
                assert response.status == 200

                # 查询使用情况
                response = await session.get(
                    f"{BASE_URL}/api/auth/feature/{feature}/usage",
                    headers=headers
                )
                assert response.status == 200
                usage = await response.json()
                assert "daily_used" in usage
                assert "monthly_used" in usage
                print(f"✓ 功能 {feature} 测试成功")

    @pytest.mark.asyncio
    async def test_admin_functions(self):
        """测试管理员功能"""
        async with aiohttp.ClientSession() as session:
            # 1. 管理员登录
            response = await session.post(
                f"{BASE_URL}/api/auth/login",
                json={
                    "email": "admin@example.com",
                    "password": "Admin@123456"
                }
            )
            assert response.status == 200
            data = await response.json()
            admin_token = data["access_token"]
            headers = {"Authorization": f"Bearer {admin_token}"}

            # 2. 获取所有用户
            response = await session.get(
                f"{BASE_URL}/api/auth/users",
                headers=headers
            )
            assert response.status == 200
            users = await response.json()
            assert isinstance(users, list)
            print("✓ 获取用户列表成功")

            # 3. 更新用户状态
            response = await session.put(
                f"{BASE_URL}/api/auth/users/519501877@qq.com/status",
                params={"is_active": "true"},
                headers=headers
            )
            assert response.status == 200
            print("✓ 更新用户状态成功")

    @pytest.mark.asyncio
    async def test_cleanup(self):
        """清理测试数据"""
        async with aiohttp.ClientSession() as session:
            headers = {"X-Test-Key": "test_key"}
            response = await session.post(
                f"{BASE_URL}/api/auth/cleanup_test_data",
                headers=headers
            )
            assert response.status == 200
            print("✓ 测试数据清理成功")

    @pytest.mark.asyncio
    async def test_all(self):
        """运行所有测试"""
        print("\n开始全套测试...\n")
        
        # 1. 用户注册和登录
        token = await self.test_user_registration_and_login()
        print("\n用户认证测试完成\n")
        
        # 2. 密码重置
        await self.test_password_reset()
        print("\n密码重置测试完成\n")
        
        # 3. 功能使用统计
        await self.test_feature_usage(token)
        print("\n功能使用测试完成\n")
        
        # 4. 管理员功能
        await self.test_admin_functions()
        print("\n管理员功能测试完成\n")
        
        # 5. 清理测试数据
        await self.test_cleanup()
        print("\n测试数据清理完成")
        
        print("\n所有测试完成！")

    @pytest.mark.asyncio
    async def test_user_stats(self):
        """测试用户统计功能"""
        async with aiohttp.ClientSession() as session:
            # 1. 管理员登录
            response = await session.post(
                f"{BASE_URL}/api/auth/login",
                json={
                    "email": "admin@example.com",
                    "password": "Admin@123456"
                }
            )
            assert response.status == 200
            data = await response.json()
            admin_token = data["access_token"]
            headers = {"Authorization": f"Bearer {admin_token}"}

            # 2. 获取用户统计
            response = await session.get(
                f"{BASE_URL}/api/auth/stats",
                headers=headers
            )
            assert response.status == 200
            stats = await response.json()
            
            # 验证统计数据格式
            assert "total_users" in stats
            assert "new_users_today" in stats
            assert "active_users_7d" in stats
            assert "role_distribution" in stats
            assert "timestamp" in stats
            print("✓ 用户统计功能测试成功")

if __name__ == "__main__":
    pytest.main(["-v", "test_all.py::TestAuthService::test_all"]) 