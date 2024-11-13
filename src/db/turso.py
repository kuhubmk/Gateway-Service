import sqlite3
import logging
import asyncio
from typing import Optional
from src.core.config import settings
import threading

logger = logging.getLogger(__name__)

class TursoClient:
    """本地 SQLite 数据库客户端"""
    _local = threading.local()
    _db_path = "data/local.db"
    
    @classmethod
    def get_client(cls):
        """获取数据库连接"""
        if not hasattr(cls._local, 'instance'):
            try:
                cls._local.instance = sqlite3.connect(cls._db_path, check_same_thread=False)
                cls._local.instance.row_factory = sqlite3.Row
                logger.info("Successfully connected to SQLite database")
            except Exception as e:
                logger.error(f"Failed to connect to SQLite: {str(e)}")
                raise
        return cls._local.instance

    @classmethod
    async def execute(cls, query: str, params: tuple = None):
        """执行 SQL 查询"""
        try:
            def _execute():
                conn = cls.get_client()
                with conn:  # 使用上下文管理器自动处理事务
                    cursor = conn.cursor()
                    if params:
                        cursor.execute(query, params)
                    else:
                        cursor.execute(query)
                    
                    # 获取结果
                    columns = [description[0] for description in cursor.description] if cursor.description else []
                    rows = cursor.fetchall() if cursor.description else []
                    return columns, rows

            loop = asyncio.get_event_loop()
            columns, rows = await loop.run_in_executor(None, _execute)
            
            # 构造结果对象
            result = type('Result', (), {
                'columns': columns,
                'rows': rows
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Query execution error: {str(e)}")
            raise

    @classmethod
    async def execute_batch(cls, queries: list):
        """批量执行 SQL 查询"""
        try:
            def _execute_batch():
                conn = cls.get_client()
                results = []
                with conn:  # 使用上下文管理器自动处理事务
                    cursor = conn.cursor()
                    for query in queries:
                        cursor.execute(query)
                        results.append(cursor.fetchall())
                return results

            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _execute_batch)
            
        except Exception as e:
            logger.error(f"Batch execution error: {str(e)}")
            raise

    @classmethod
    def close(cls):
        """关闭数据库连接"""
        if hasattr(cls._local, 'instance'):
            try:
                cls._local.instance.close()
                delattr(cls._local, 'instance')
                logger.info("Closed SQLite database connection")
            except Exception as e:
                logger.error(f"Error closing database connection: {str(e)}")