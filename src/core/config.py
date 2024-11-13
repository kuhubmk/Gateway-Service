from pydantic_settings import BaseSettings
from typing import Dict, Any

class Settings(BaseSettings):
    # 数据库配置
    TURSO_DB_URL: str
    TURSO_DB_AUTH_TOKEN: str
    
    # JWT配置
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # 管理员配置
    ADMIN_EMAIL: str
    ADMIN_PASSWORD: str
    
    # Tyk配置
    TYK_GATEWAY_URL: str
    TYK_DASHBOARD_URL: str
    TYK_SECRET: str
    TYK_ORG_ID: str
    TYK_DEFAULT_POLICY_ID: str
    TYK_BASIC_POLICY_ID: str
    TYK_PREMIUM_POLICY_ID: str
    
    # SMTP配置
    smtp_server: str = "smtp.qq.com"
    smtp_port: int = 465
    sender_email: str = "519501877@qq.com"
    receiver_email: str = "519501877@qq.com"
    password: str = "ahpooutarreocbea"  # QQ邮箱授权码
    
    # 前端URL
    FRONTEND_URL: str = "http://localhost:3000"
    
    # 测试配置
    TEST_KEY: str = "test_key"
    
    # 日志配置
    LOG_LEVEL: str = "INFO"
    
    # 功能限制配置
    FEATURE_LIMITS: Dict[str, Dict[str, Dict[str, int]]] = {
        "SPEECH_TO_TEXT": {
            "BASIC": {"daily": 3, "monthly": 50},
            "PREMIUM": {"daily": 10, "monthly": 200}
        },
        "TEXT_PROCESS": {
            "BASIC": {"daily": 1000, "monthly": 20000},
            "PREMIUM": {"daily": 10000, "monthly": 200000}
        },
        "TEXT_TO_SPEECH": {
            "BASIC": {"daily": 10, "monthly": 200},
            "PREMIUM": {"daily": 100, "monthly": 2000}
        },
        "IMAGE_GENERATE": {
            "BASIC": {"daily": 5, "monthly": 100},
            "PREMIUM": {"daily": 50, "monthly": 1000}
        }
    }
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings() 