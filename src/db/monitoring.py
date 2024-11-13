from functools import wraps
import time
from prometheus_client import Histogram

DB_OPERATION_LATENCY = Histogram('db_operation_duration_seconds', 'Database operation latency', ['operation'])

def monitor_db_operation(operation_name):
    """数据库操作性能监控装饰器"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                DB_OPERATION_LATENCY.labels(operation=operation_name).observe(duration)
                return result
            except Exception as e:
                duration = time.time() - start_time
                DB_OPERATION_LATENCY.labels(operation=operation_name).observe(duration)
                raise
        return wrapper
    return decorator 