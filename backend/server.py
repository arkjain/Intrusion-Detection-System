from fastapi import FastAPI, APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import json
import asyncio
import random
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import re

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="Intrusion Detection System", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Enums for IDS
class ThreatType(str, Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss_attack"
    DDoS = "ddos"
    MALWARE = "malware"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    ANOMALY = "anomaly"

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ConnectionStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    SUSPICIOUS = "suspicious"

# Data Models
class NetworkEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    connection_status: ConnectionStatus
    flags: Optional[List[str]] = []
    payload_snippet: Optional[str] = None

class ThreatAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    threat_type: ThreatType
    severity: SeverityLevel
    source_ip: str
    dest_ip: str
    description: str
    signature_matched: Optional[str] = None
    is_anomaly: bool = False
    confidence_score: float = 0.0
    event_ids: List[str] = []
    resolved: bool = False

class NetworkStatistics(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_connections: int
    blocked_connections: int
    suspicious_connections: int
    total_threats: int
    threats_by_type: Dict[str, int]
    top_source_ips: List[Dict[str, Any]]
    bandwidth_usage: float

# Connection Manager for WebSocket
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Remove disconnected connections
                self.active_connections.remove(connection)

manager = ConnectionManager()

# Signature-based Detection Rules
THREAT_SIGNATURES = {
    "sql_injection": [
        r"(?i)(union.*select|insert.*into|delete.*from|drop.*table)",
        r"(?i)('.*or.*'='|'.*and.*'=')",
        r"(?i)(exec\(|execute\()",
    ],
    "xss_attack": [
        r"(?i)(<script.*>|javascript:|on\w+\s*=)",
        r"(?i)(alert\(|confirm\(|prompt\()",
        r"(?i)(<img.*onerror|<iframe.*src)",
    ],
    "port_scan": [
        r"SYN.*FIN",  # TCP flag combination
        r"NULL.*scan",  # NULL scan pattern
    ],
    "brute_force": [
        r"(?i)(admin|root|administrator)",
        r"(?i)(password|login|auth)",
    ]
}

# Network Traffic Simulator
class NetworkTrafficSimulator:
    def __init__(self):
        self.legitimate_ips = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "10.0.0.5"]
        self.malicious_ips = ["203.0.113.5", "198.51.100.7", "192.0.2.15", "185.220.101.3"]
        self.common_ports = [80, 443, 22, 21, 25, 53, 993, 995, 8080, 3389]
        self.protocols = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP"]
        
    def generate_normal_traffic(self) -> NetworkEvent:
        source_ip = random.choice(self.legitimate_ips)
        dest_ip = random.choice(self.legitimate_ips)
        source_port = random.randint(1024, 65535)
        dest_port = random.choice(self.common_ports)
        
        return NetworkEvent(
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=random.choice(self.protocols),
            packet_size=random.randint(64, 1500),
            connection_status=ConnectionStatus.ALLOWED,
            flags=["SYN", "ACK"] if random.random() > 0.3 else ["SYN"]
        )
    
    def generate_malicious_traffic(self) -> NetworkEvent:
        source_ip = random.choice(self.malicious_ips)
        dest_ip = random.choice(self.legitimate_ips)
        
        # Simulate various attack patterns
        attack_type = random.choice(["port_scan", "brute_force", "ddos"])
        
        if attack_type == "port_scan":
            return NetworkEvent(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=random.randint(1, 1024),  # Scanning low ports
                protocol="TCP",
                packet_size=random.randint(40, 80),
                connection_status=ConnectionStatus.SUSPICIOUS,
                flags=["SYN"],
                payload_snippet="port_scan_attempt"
            )
        elif attack_type == "brute_force":
            return NetworkEvent(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=22,  # SSH brute force
                protocol="SSH",
                packet_size=random.randint(100, 300),
                connection_status=ConnectionStatus.BLOCKED,
                flags=["PSH", "ACK"],
                payload_snippet="admin:password123"
            )
        else:  # ddos
            return NetworkEvent(
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=random.randint(1024, 65535),
                dest_port=80,
                protocol="HTTP",
                packet_size=random.randint(1000, 1500),
                connection_status=ConnectionStatus.BLOCKED,
                flags=["SYN"],
                payload_snippet="GET / HTTP/1.1"
            )

# Detection Engine
class DetectionEngine:
    def __init__(self):
        self.baseline_stats = {"connections_per_minute": 100, "avg_packet_size": 800}
        
    def signature_detection(self, event: NetworkEvent) -> Optional[ThreatAlert]:
        if not event.payload_snippet:
            return None
            
        for threat_type, patterns in THREAT_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, event.payload_snippet):
                    severity = SeverityLevel.HIGH if threat_type in ["sql_injection", "xss_attack"] else SeverityLevel.MEDIUM
                    
                    return ThreatAlert(
                        threat_type=ThreatType(threat_type),
                        severity=severity,
                        source_ip=event.source_ip,
                        dest_ip=event.dest_ip,
                        description=f"Signature-based detection: {threat_type} from {event.source_ip}",
                        signature_matched=pattern,
                        confidence_score=0.95,
                        event_ids=[event.id]
                    )
        return None
    
    def anomaly_detection(self, event: NetworkEvent, recent_events: List[NetworkEvent]) -> Optional[ThreatAlert]:
        # Simple anomaly detection based on connection patterns
        source_events = [e for e in recent_events if e.source_ip == event.source_ip]
        
        # Check for port scanning (multiple destination ports from same IP)
        if len(source_events) >= 5:
            unique_ports = len(set(e.dest_port for e in source_events))
            if unique_ports >= 5:
                return ThreatAlert(
                    threat_type=ThreatType.PORT_SCAN,
                    severity=SeverityLevel.HIGH,
                    source_ip=event.source_ip,
                    dest_ip=event.dest_ip,
                    description=f"Port scan detected from {event.source_ip} - {unique_ports} ports scanned",
                    is_anomaly=True,
                    confidence_score=0.8,
                    event_ids=[e.id for e in source_events]
                )
        
        # Check for DDoS (high connection rate)
        if len(source_events) >= 10:  # More than 10 connections in recent window
            return ThreatAlert(
                threat_type=ThreatType.DDoS,
                severity=SeverityLevel.CRITICAL,
                source_ip=event.source_ip,
                dest_ip=event.dest_ip,
                description=f"Potential DDoS attack from {event.source_ip} - {len(source_events)} connections",
                is_anomaly=True,
                confidence_score=0.7,
                event_ids=[e.id for e in source_events]
            )
        
        return None

# Initialize components
traffic_simulator = NetworkTrafficSimulator()
detection_engine = DetectionEngine()

# Storage for recent events (in production, use proper caching)
recent_events = []
MAX_RECENT_EVENTS = 1000

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Intrusion Detection System API", "version": "1.0.0"}

@api_router.get("/events", response_model=List[NetworkEvent])
async def get_network_events(limit: int = 100):
    events = await db.network_events.find().sort("timestamp", -1).limit(limit).to_list(limit)
    return [NetworkEvent(**event) for event in events]

@api_router.get("/alerts", response_model=List[ThreatAlert])
async def get_threat_alerts(limit: int = 50, resolved: Optional[bool] = None):
    query = {}
    if resolved is not None:
        query["resolved"] = resolved
    
    alerts = await db.threat_alerts.find(query).sort("timestamp", -1).limit(limit).to_list(limit)
    return [ThreatAlert(**alert) for alert in alerts]

@api_router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    result = await db.threat_alerts.update_one(
        {"id": alert_id}, 
        {"$set": {"resolved": True}}
    )
    return {"success": result.modified_count > 0}

@api_router.get("/statistics", response_model=NetworkStatistics)
async def get_network_statistics():
    # Calculate statistics from recent events
    total_events = await db.network_events.count_documents({})
    blocked_count = await db.network_events.count_documents({"connection_status": "blocked"})
    suspicious_count = await db.network_events.count_documents({"connection_status": "suspicious"})
    total_threats = await db.threat_alerts.count_documents({"resolved": False})
    
    # Aggregate threat types
    threat_pipeline = [
        {"$match": {"resolved": False}},
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}}
    ]
    threat_types = await db.threat_alerts.aggregate(threat_pipeline).to_list(None)
    threats_by_type = {item["_id"]: item["count"] for item in threat_types}
    
    # Top source IPs
    ip_pipeline = [
        {"$group": {"_id": "$source_ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    top_ips = await db.network_events.aggregate(ip_pipeline).to_list(None)
    top_source_ips = [{"ip": item["_id"], "count": item["count"]} for item in top_ips]
    
    return NetworkStatistics(
        total_connections=total_events,
        blocked_connections=blocked_count,
        suspicious_connections=suspicious_count,
        total_threats=total_threats,
        threats_by_type=threats_by_type,
        top_source_ips=top_source_ips,
        bandwidth_usage=random.uniform(50.0, 95.0)  # Simulated bandwidth
    )

# WebSocket for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task for traffic simulation and detection
async def traffic_monitoring_task():
    global recent_events
    
    while True:
        # Generate network traffic (90% legitimate, 10% malicious)
        if random.random() < 0.9:
            event = traffic_simulator.generate_normal_traffic()
        else:
            event = traffic_simulator.generate_malicious_traffic()
        
        # Store event
        event_dict = event.dict()
        event_dict['timestamp'] = event.timestamp.isoformat()
        await db.network_events.insert_one(event_dict)
        
        # Add to recent events for anomaly detection
        recent_events.append(event)
        if len(recent_events) > MAX_RECENT_EVENTS:
            recent_events.pop(0)
        
        # Run detection engines
        alerts = []
        
        # Signature-based detection
        sig_alert = detection_engine.signature_detection(event)
        if sig_alert:
            alerts.append(sig_alert)
        
        # Anomaly-based detection
        anom_alert = detection_engine.anomaly_detection(event, recent_events[-20:])  # Check last 20 events
        if anom_alert:
            alerts.append(anom_alert)
        
        # Store alerts and broadcast
        for alert in alerts:
            alert_dict = alert.dict()
            alert_dict['timestamp'] = alert.timestamp.isoformat()
            await db.threat_alerts.insert_one(alert_dict)
            
            # Broadcast alert to WebSocket clients
            alert_message = {
                "type": "threat_alert",
                "data": alert_dict
            }
            await manager.broadcast(json.dumps(alert_message))
        
        # Broadcast network event
        event_message = {
            "type": "network_event",
            "data": event_dict
        }
        await manager.broadcast(json.dumps(event_message))
        
        # Wait before generating next event
        await asyncio.sleep(random.uniform(0.5, 2.0))

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Start background task
@app.on_event("startup")
async def startup_event():
    # Start the traffic monitoring task
    asyncio.create_task(traffic_monitoring_task())

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()