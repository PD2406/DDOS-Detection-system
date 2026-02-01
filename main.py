"""
FastAPI main application
"""

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
from datetime import datetime
import logging
from typing import List, Dict, Any

from api.routes import auth, detect, live_traffic, mitigate, monitor
from api.middleware.rate_limiter import RateLimiter
from core.auth.authentication import verify_token
from config.settings import settings

logger = logging.getLogger(__name__)
security = HTTPBearer()

app = FastAPI(
    title="DDoS Detection API",
    description="Real-time DDoS attack detection and mitigation API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware (temporarily disabled for testing)
# app.add_middleware(
#     RateLimiter,
#     requests=settings.RATE_LIMIT_REQUESTS,
#     period=settings.RATE_LIMIT_PERIOD
# )

# Include routers
app.include_router(auth, prefix="/auth", tags=["Authentication"])
app.include_router(detect, prefix="/detect", tags=["Detection"])
app.include_router(live_traffic, prefix="/live", tags=["Live Traffic"])
app.include_router(mitigate, prefix="/mitigate", tags=["Mitigation"])
app.include_router(monitor, prefix="/monitor", tags=["Monitoring"])

class ConnectionManager:
    """WebSocket connection manager"""
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.append(connection)
        
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "DDoS Detection API",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back or process data
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")

@app.get("/protected")
async def protected_route(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Example protected route"""
    token = credentials.credentials
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return {
        "message": "Access granted",
        "user": payload.get("sub"),
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(
        "api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        workers=settings.API_WORKERS
    )