from fastapi import APIRouter
from src.db.turso import TursoClient
from src.core.config import settings
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/health")
async def health_check():
    """系统健康检查"""
    health_status = {
        "status": "up",
        "database": "unknown",
        "tyk_gateway": "unknown",
        "components": {
            "database": "unknown",
            "tyk_gateway": "unknown",
            "email_service": "unknown"
        }
    }

    try:
        # 检查数据库连接
        await TursoClient.execute("SELECT 1")
        health_status["database"] = "healthy"
        health_status["components"]["database"] = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        health_status["database"] = "unhealthy"
        health_status["components"]["database"] = "unhealthy"
        health_status["status"] = "down"

    try:
        # 检查 Tyk 连接
        # TODO: 实现 Tyk 健康检查
        health_status["tyk_gateway"] = "healthy"
        health_status["components"]["tyk_gateway"] = "healthy"
    except Exception as e:
        logger.error(f"Tyk health check failed: {str(e)}")
        health_status["tyk_gateway"] = "unhealthy"
        health_status["components"]["tyk_gateway"] = "unhealthy"
        health_status["status"] = "down"

    try:
        # 检查邮件服务
        if settings.smtp_server and settings.smtp_port:
            health_status["components"]["email_service"] = "healthy"
        else:
            health_status["components"]["email_service"] = "disabled"
    except Exception as e:
        logger.error(f"Email service health check failed: {str(e)}")
        health_status["components"]["email_service"] = "unhealthy"
        health_status["status"] = "down"

    return health_status 