from fastapi import Request
import time
import logging
from prometheus_client import Counter, Histogram

# 定义监控指标
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency', ['method', 'endpoint'])

async def monitoring_middleware(request: Request, call_next):
    """API性能监控中间件"""
    start_time = time.time()
    
    # 记录请求开始
    method = request.method
    endpoint = request.url.path
    
    try:
        response = await call_next(request)
        
        # 记录请求结束
        duration = time.time() - start_time
        status = response.status_code
        
        # 更新监控指标
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()
        REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(duration)
        
        return response
        
    except Exception as e:
        duration = time.time() - start_time
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=500).inc()
        REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(duration)
        raise 