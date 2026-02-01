# api/websocket_manager.py
"""
WebSocket connection manager for real-time updates
"""
import asyncio
import json
from typing import Dict, List
from fastapi import WebSocket
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {
            "monitoring": [],
            "alerts": [],
            "dashboard": []
        }
    
    async def connect(self, websocket: WebSocket, channel: str = "monitoring"):
        """Accept WebSocket connection and add to channel"""
        await websocket.accept()
        if channel in self.active_connections:
            self.active_connections[channel].append(websocket)
            logger.info(f"New WebSocket connection to {channel} channel")
        return True
    
    def disconnect(self, websocket: WebSocket, channel: str = "monitoring"):
        """Remove WebSocket from channel"""
        if channel in self.active_connections and websocket in self.active_connections[channel]:
            self.active_connections[channel].remove(websocket)
            logger.info(f"WebSocket disconnected from {channel} channel")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to specific WebSocket"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")
    
    async def broadcast(self, channel: str, message: dict):
        """Broadcast message to all connections in channel"""
        if channel in self.active_connections:
            disconnected = []
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to broadcast to connection: {e}")
                    disconnected.append(connection)
            
            # Clean up disconnected clients
            for connection in disconnected:
                self.disconnect(connection, channel)
    
    def get_connection_count(self, channel: str = None) -> int:
        """Get number of active connections"""
        if channel:
            return len(self.active_connections.get(channel, []))
        return sum(len(connections) for connections in self.active_connections.values())

# Global manager instance
manager = ConnectionManager()