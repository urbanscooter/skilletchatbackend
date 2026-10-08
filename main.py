import os
import re
import time
import json
import base64
import logging
from typing import Dict, Set, Optional, Tuple
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, status, Query, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import firebase_admin
from firebase_admin import auth as fb_auth

ENV = os.getenv("ENVIRONMENT", "production")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
MAX_PAYLOAD_BYTES = int(os.getenv("MAX_PAYLOAD_BYTES", "65536"))
RATE_LIMIT_CAPACITY = int(os.getenv("RATE_LIMIT_CAPACITY", "8"))
RATE_LIMIT_REFILL_RATE = float(os.getenv("RATE_LIMIT_REFILL_RATE", "4.0"))
MAX_CLIENTS_PER_ROOM = int(os.getenv("MAX_CLIENTS_PER_ROOM", "100"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SECURITY_AUDIT] %(message)s"
)
logger = logging.getLogger("ZeroKnowledgeGateway")

if not firebase_admin._apps:
    try:
        firebase_admin.initialize_app()
        logger.info("Firebase Security Provider initialized successfully.")
    except Exception as exc:
        logger.warning(f"Firebase Admin running in sandbox/fallback mode: {exc}")

app = FastAPI(
    title="SkilletChat Zero-Knowledge Relay",
    version="2.0.0",
    docs_url=None if ENV == "production" else "/docs",
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
    return response

BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=]+$")

class PayloadSanitizer:
    @staticmethod
    def is_valid_base64(value: str) -> bool:
        if not value or len(value) % 4 != 0:
            return False
        return bool(BASE64_PATTERN.match(value))

    @classmethod
    def inspect_encrypted_packet(cls, raw_data: str) -> Tuple[bool, str]:
        if len(raw_data.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            return False, "PAYLOAD_TOO_LARGE"

        try:
            payload = json.loads(raw_data)
        except Exception:
            return False, "INVALID_JSON"

        cipher_field = payload.get("text") or payload.get("payload")
        if not cipher_field or not isinstance(cipher_field, str):
            return False, "MISSING_CIPHER_PAYLOAD"

        parts = cipher_field.split(":")
        if len(parts) != 3 or parts[0] != "v2":
            return False, "NON_COMPLIANT_PROTOCOL"

        iv_b64, body_b64 = parts[1], parts[2]
        if not (cls.is_valid_base64(iv_b64) and cls.is_valid_base64(body_b64)):
            return False, "CORRUPTED_BASE64_ENCODING"

        try:
            if len(base64.b64decode(iv_b64)) != 12:
                return False, "INVALID_IV_LENGTH"
        except Exception:
            return False, "IV_DECODE_FAILURE"

        return True, "OK"

class TokenBucketLimiter:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens: Dict[WebSocket, float] = {}
        self.last_update: Dict[WebSocket, float] = {}

    def allow(self, ws: WebSocket) -> bool:
        now = time.time()
        tokens = self.tokens.get(ws, self.capacity)
        last = self.last_update.get(ws, now)

        elapsed = now - last
        tokens = min(self.capacity, tokens + elapsed * self.refill_rate)
        self.last_update[ws] = now

        if tokens >= 1.0:
            self.tokens[ws] = tokens - 1.0
            return True
        else:
            self.tokens[ws] = tokens
            return False

    def evict(self, ws: WebSocket):
        self.tokens.pop(ws, None)
        self.last_update.pop(ws, None)

class HardenedConnectionHub:
    def __init__(self):
        self.active_rooms: Dict[str, Set[WebSocket]] = {}
        self.client_meta: Dict[WebSocket, Tuple[str, str]] = {}
        self.limiter = TokenBucketLimiter(RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_RATE)

    async def register(self, ws: WebSocket, chat_id: str, uid: str) -> bool:
        room = self.active_rooms.setdefault(chat_id, set())
        if len(room) >= MAX_CLIENTS_PER_ROOM:
            logger.warning(f"Connection refused: Room {chat_id} is full.")
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return False

        await ws.accept()
        room.add(ws)
        self.client_meta[ws] = (chat_id, uid)
        logger.info(f"Secure session opened: UID={uid[:6]}*** | Room={chat_id}")
        return True

    def unregister(self, ws: WebSocket):
        if ws in self.client_meta:
            chat_id, uid = self.client_meta.pop(ws)
            if chat_id in self.active_rooms:
                self.active_rooms[chat_id].discard(ws)
                if not self.active_rooms[chat_id]:
                    del self.active_rooms[chat_id]
            self.limiter.evict(ws)
            logger.info(f"Secure session terminated: UID={uid[:6]}*** | Room={chat_id}")

    async def broadcast_cipher(self, chat_id: str, data: str, sender: WebSocket):
        if chat_id not in self.active_rooms:
            return

        dead_nodes = []
        for socket in list(self.active_rooms[chat_id]):
            if socket != sender:
                try:
                    await socket.send_text(data)
                except Exception:
                    dead_nodes.append(socket)

        for stale in dead_nodes:
            self.unregister(stale)

hub = HardenedConnectionHub()

def authenticate_client_token(token: Optional[str]) -> Optional[str]:
    if not token:
        if ENV == "development":
            return "dev_guest_client"
        return None
    try:
        claims = fb_auth.verify_id_token(token, check_revoked=True)
        return claims.get("uid")
    except Exception as err:
        logger.warning(f"Authentication failure: {err}")
        return None

@app.get("/health", response_class=JSONResponse)
def health_probe():
    return {
        "status": "healthy",
        "zero_knowledge": True,
        "active_rooms": len(hub.active_rooms),
        "protocol_version": "v2"
    }

@app.websocket("/ws/{chat_id}")
async def zero_knowledge_gateway(
    websocket: WebSocket,
    chat_id: str,
    token: Optional[str] = Query(None)
):
    if not re.match(r"^[A-Za-z0-9_\-]{3,64}$", chat_id):
        await websocket.close(code=status.WS_1003_UNSUPPORTED_DATA)
        return

    uid = authenticate_client_token(token)
    if not uid:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    success = await hub.register(websocket, chat_id, uid)
    if not success:
        return

    try:
        while True:
            raw_packet = await websocket.receive_text()

            if not hub.limiter.allow(websocket):
                logger.warning(f"Rate limit triggered for UID={uid[:6]}***")
                continue

            is_valid, reason = PayloadSanitizer.inspect_encrypted_packet(raw_packet)
            if not is_valid:
                logger.warning(f"Dropped non-compliant packet from {uid[:6]}***: {reason}")
                continue

            await hub.broadcast_cipher(chat_id, raw_packet, sender=websocket)

    except WebSocketDisconnect:
        hub.unregister(websocket)
    except Exception as exc:
        logger.error(f"Socket abnormal termination: {exc}")
        hub.unregister(websocket)
