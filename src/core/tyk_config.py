from pydantic_settings import BaseSettings

class TykSettings(BaseSettings):
    TYK_GATEWAY_URL: str = "http://tyk-gateway:8080"
    TYK_DASHBOARD_URL: str = "http://tyk-dashboard:3000"
    TYK_SECRET: str = ""
    TYK_ORG_ID: str = ""
    TYK_DEFAULT_POLICY_ID: str = ""
    
    class Config:
        env_file = ".env"
        case_sensitive = True