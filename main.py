from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.user import router as user_router
from src.api.health import router as health_router
from src.middleware.monitoring import monitoring_middleware
from prometheus_client import make_asgi_app

app = FastAPI()

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 添加监控中间件
app.middleware("http")(monitoring_middleware)

# 添加 Prometheus 指标路由
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# 注册路由
app.include_router(user_router, prefix="/api/auth")
app.include_router(health_router)

@app.on_event("startup")
async def startup_event():
    from src.db.users import UserDB
    await UserDB.init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)