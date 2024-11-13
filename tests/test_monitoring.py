import pytest
import aiohttp
import asyncio
from datetime import datetime
import time

BASE_URL = "http://localhost:8000"

class TestMonitoring:
    @pytest.mark.asyncio
    async def test_health_check(self):
        """测试健康检查接口"""
        async with aiohttp.ClientSession() as session:
            response = await session.get(f"{BASE_URL}/health")
            assert response.status == 200
            data = await response.json()
            
            # 验证健康检查响应格式
            assert "status" in data
            assert "database" in data
            assert "tyk_gateway" in data
            assert "components" in data
            
            # 验证所有组件状态
            assert data["status"] == "up"
            print("✓ 健康检查接口测试通过")

    @pytest.mark.asyncio
    async def test_performance_metrics(self):
        """测试性能指标收集"""
        async with aiohttp.ClientSession() as session:
            # 1. 获取初始指标
            response = await session.get(f"{BASE_URL}/metrics")
            assert response.status == 200
            initial_metrics = await response.text()
            
            # 2. 执行一些操作生成指标
            test_endpoints = [
                ("/api/auth/register", "POST", {"email": "test@example.com", "password": "Test123!@#"}),
                ("/api/auth/login", "POST", {"email": "admin@example.com", "password": "Admin@123456"}),
                ("/health", "GET", None)
            ]
            
            for endpoint, method, data in test_endpoints:
                start_time = time.time()
                if method == "GET":
                    await session.get(f"{BASE_URL}{endpoint}")
                else:
                    await session.post(f"{BASE_URL}{endpoint}", json=data)
                duration = time.time() - start_time
                print(f"✓ 端点 {endpoint} 响应时间: {duration:.3f}秒")
            
            # 3. 获取更新后的指标
            response = await session.get(f"{BASE_URL}/metrics")
            assert response.status == 200
            updated_metrics = await response.text()
            
            # 验证指标是否被正确记录
            assert "http_requests_total" in updated_metrics
            assert "http_request_duration_seconds" in updated_metrics
            print("✓ 性能指标收集测试通过")

    @pytest.mark.asyncio
    async def test_database_monitoring(self):
        """测试数据库操作监控"""
        async with aiohttp.ClientSession() as session:
            # 1. 登录获取token
            response = await session.post(
                f"{BASE_URL}/api/auth/login",
                json={
                    "email": "admin@example.com",
                    "password": "Admin@123456"
                }
            )
            assert response.status == 200
            data = await response.json()
            headers = {"Authorization": f"Bearer {data['access_token']}"}
            
            # 2. 执行数据库操作
            start_time = time.time()
            response = await session.get(
                f"{BASE_URL}/api/auth/users",
                headers=headers
            )
            duration = time.time() - start_time
            print(f"✓ 数据库查询响应时间: {duration:.3f}秒")
            
            # 3. 获取数据库监控指标
            response = await session.get(f"{BASE_URL}/metrics")
            metrics = await response.text()
            
            # 验证数据库指标
            assert "db_operation_duration_seconds" in metrics
            print("✓ 数据库监控指标测试通过")

    @pytest.mark.asyncio
    async def test_all_monitoring(self):
        """运行所有监控测试"""
        print("\n开始监控系统测试...\n")
        
        # 1. 健康检查
        await self.test_health_check()
        print("\n健康检查测试完成\n")
        
        # 2. 性能指标
        await self.test_performance_metrics()
        print("\n性能指标测试完成\n")
        
        # 3. 数据库监控
        await self.test_database_monitoring()
        print("\n数据库监控测试完成\n")
        
        print("\n所有监控测试完成！")

if __name__ == "__main__":
    pytest.main(["-v", "test_monitoring.py::TestMonitoring::test_all_monitoring"]) 