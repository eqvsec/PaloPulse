# Project: PaloPulse
# Copyright (c) 2026 @eqvsec
# Licensed under MIT

import asyncio
import socket
import os
import yaml
import geoip2.database
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import socketio
import uvicorn
import concurrent.futures
import csv
from io import StringIO

# --- LOAD CONFIGURATION ---
try:
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    print("❌ CRITICAL ERROR: config.yaml not found!")
    exit(1)

# --- LOGGING SETUP ---
def setup_logging():
    """Configure logging based on config.yaml settings"""
    log_config = config.get('logging', {})
    
    if not log_config.get('enabled', False):
        # Logging disabled - use basic config that only shows critical errors
        logging.basicConfig(level=logging.CRITICAL)
        return None
    
    # Create logs directory if it doesn't exist
    log_file = log_config.get('file_path', 'logs/dashboard.log')
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Get logging level
    log_level_str = log_config.get('level', 'INFO').upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    
    # Get rotation settings
    max_bytes = log_config.get('max_size_mb', 5) * 1024 * 1024  # Convert MB to bytes
    backup_count = log_config.get('backup_count', 3)
    
    # Create rotating file handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    
    # Create console handler for terminal output
    console_handler = logging.StreamHandler()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Initialize logging
logger = setup_logging()

# Helper function for logging
def log(level, message, **kwargs):
    """Unified logging function"""
    if logger:
        log_func = getattr(logger, level.lower(), logger.info)
        if kwargs:
            message = f"{message} | {kwargs}"
        log_func(message)

# Extract config variables
UDP_IP = config['server']['udp_ip']
UDP_PORT = config['server']['udp_port']
GEOIP_DB_PATH = config['geoip']['db_path']
ALLOWED_ZONES = config.get('allowed_zones', [])
RULE_COLORS = config.get('rule_colors', {})
THREAT_COLORS = config.get('threat_colors', {})
TRAFFIC_ENABLED = config['log_types'].get('traffic_enabled', True)
THREAT_ENABLED = config['log_types'].get('threat_enabled', True)

# --- PROTOCOL MAPPING ---
PROTOCOL_MAP = {
    '1': 'ICMP', '6': 'TCP', '17': 'UDP', '47': 'GRE', 
    '50': 'ESP', '51': 'AH', '58': 'ICMPv6', '89': 'OSPF',
    '41': 'IPv6', '2': 'IGMP'
}

# --- SETUP ---
app = FastAPI()

if not os.path.exists("static"): os.makedirs("static")
if not os.path.exists("templates"): os.makedirs("templates")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
socket_app = socketio.ASGIApp(sio, app)

try:
    reader = geoip2.database.Reader(GEOIP_DB_PATH)
    log('info', "✅ GeoIP Database Loaded", path=GEOIP_DB_PATH)
except FileNotFoundError:
    log('error', f"❌ ERROR: {GEOIP_DB_PATH} not found. Please download it.")
    print(f"❌ ERROR: {GEOIP_DB_PATH} not found. Please download it.")
    reader = None

dns_cache = {}
executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

# Statistics counters for monitoring
stats = {
    'traffic_logs_processed': 0,
    'threat_logs_processed': 0,
    'geoip_lookups': 0,
    'geoip_failures': 0,
    'dns_cache_hits': 0,
    'dns_resolutions': 0,
    'total_events_emitted': 0,
    'start_time': datetime.now()
}

def resolve_hostname(ip):
    """Resolves IP to hostname with caching to prevent lag."""
    if ip in dns_cache:
        stats['dns_cache_hits'] += 1
        return dns_cache[ip]
    
    stats['dns_resolutions'] += 1
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if '.' in hostname: hostname = hostname.split('.')[0]
        dns_cache[ip] = hostname
        log('debug', f"DNS resolved: {ip} -> {hostname}")
        return hostname
    except (socket.herror, socket.gaierror) as e:
        log('debug', f"DNS resolution failed for {ip}: {e}")
        dns_cache[ip] = ip
        return ip

def get_color_for_rule(rule_name):
    """Checks rule name against config patterns to determine color."""
    if not rule_name: return "#ff0055"
    
    for color, patterns in RULE_COLORS.items():
        for pattern in patterns:
            if pattern.lower() in rule_name.lower():
                log('debug', f"Rule color match: {rule_name} -> {color}")
                return color
    return "#ff0055"

def get_color_for_threat(severity):
    """Maps threat severity to color."""
    severity_lower = severity.lower() if severity else "medium"
    return THREAT_COLORS.get(severity_lower, THREAT_COLORS.get('medium', '#ffaa00'))

def log_statistics():
    """Log current statistics - called periodically"""
    uptime = datetime.now() - stats['start_time']
    log('info', 
        f"📊 STATS | Traffic: {stats['traffic_logs_processed']} | "
        f"Threats: {stats['threat_logs_processed']} | "
        f"Events: {stats['total_events_emitted']} | "
        f"GeoIP: {stats['geoip_lookups']} ({stats['geoip_failures']} failures) | "
        f"DNS Cache: {len(dns_cache)} entries ({stats['dns_cache_hits']} hits) | "
        f"Uptime: {uptime}"
    )

def parse_csv_line(log_line):
    """Parse CSV log line respecting quoted fields that contain commas"""
    try:
        # Use Python's CSV parser to handle quoted fields properly
        reader = csv.reader(StringIO(log_line), quotechar='"', delimiter=',')
        fields = next(reader)
        #print("CSV FIELDS:", fields) # only here for debugging
        return fields
    except Exception as e:
        log('warning', f"CSV parsing failed, falling back to simple split: {e}")
        # Fallback to simple split if CSV parsing fails
        return log_line.replace('"', '').split(',')

# --- SYSLOG LISTENER ---
async def syslog_listener():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((UDP_IP, UDP_PORT))
        sock.setblocking(False)

        log('info', f"📡 Listening for Syslog on {UDP_IP}:{UDP_PORT}")
        print(f"📡 Listening for Syslog on {UDP_IP}:{UDP_PORT}...")
        
        if TRAFFIC_ENABLED:
            log('info', "✅ Traffic Log Processing: ENABLED")
            print(f"✅ Traffic Log Processing: ENABLED")
        if THREAT_ENABLED:
            log('info', "✅ Threat Log Processing: ENABLED")
            print(f"✅ Threat Log Processing: ENABLED")
        if ALLOWED_ZONES:
            log('info', f"🛡️ Zone Filtering Active: {ALLOWED_ZONES}")
            print(f"🛡️ Zone Filtering Active: Allowing {ALLOWED_ZONES}")
        else:
            log('info', "🌍 Zone Filtering Disabled: Showing ALL traffic")
            print(f"🌍 Zone Filtering Disabled: Showing ALL traffic.")

        loop = asyncio.get_running_loop()
        
        # Statistics logging task (every 5 minutes)
        last_stats_time = datetime.now()

        while True:
            try:
                data = await loop.sock_recv(sock, 4096)
                log_line = data.decode("utf-8", errors="ignore")
                
                # Use proper CSV parsing to handle quoted fields with commas
                fields = parse_csv_line(log_line)
                
                # Log stats every 5 minutes
                if (datetime.now() - last_stats_time).seconds >= 300:
                    log_statistics()
                    last_stats_time = datetime.now()
                
                if len(fields) > 30:
                    log_type = fields[3] if len(fields) > 3 else ""
                    
                    # --- TRAFFIC LOG PROCESSING ---
                    if TRAFFIC_ENABLED and log_type == "TRAFFIC":
                        if 'deny' in log_line or 'drop' in log_line:
                            try:
                                stats['traffic_logs_processed'] += 1
                                
                                raw_time = fields[1]
                                src_ip = fields[7] 
                                dst_ip = fields[8]
                                rule_name = fields[11]
                                app_id = fields[14]
                                src_zone = fields[16]
                                dst_port = fields[25]
                                
                                raw_proto = fields[29].lower()
                                if raw_proto in PROTOCOL_MAP: 
                                    proto = PROTOCOL_MAP[raw_proto]
                                elif raw_proto.isdigit(): 
                                    proto = f"PROTO-{raw_proto}"
                                else: 
                                    proto = raw_proto.upper()

                                if ALLOWED_ZONES and src_zone not in ALLOWED_ZONES:
                                    log('debug', f"Filtered out zone: {src_zone} from {src_ip}")
                                    continue

                                event_color = get_color_for_rule(rule_name)

                                try: 
                                    clean_time = raw_time.split(' ')[1]
                                except: 
                                    clean_time = datetime.now().strftime("%H:%M:%S")

                                dst_host = await loop.run_in_executor(executor, resolve_hostname, dst_ip)

                                payload = {
                                    "log_type": "traffic",
                                    "timestamp": clean_time,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "dst_host": dst_host,
                                    "dst_port": dst_port,
                                    "proto": proto,
                                    "app": app_id,
                                    "rule": rule_name,
                                    "color": event_color
                                }

                                if reader:
                                    try:
                                        stats['geoip_lookups'] += 1
                                        response = reader.city(src_ip)
                                        payload.update({
                                            "country": response.country.name,
                                            "iso_code": response.country.iso_code,
                                            "lat": response.location.latitude,
                                            "lon": response.location.longitude
                                        })
                                        log('debug', f"Traffic event: {src_ip} ({response.country.name}) -> {dst_host}:{dst_port} | Rule: {rule_name}")
                                        stats['total_events_emitted'] += 1
                                        await sio.emit('threat_event', payload)
                                    except (ValueError, geoip2.errors.AddressNotFoundError) as e:
                                        stats['geoip_failures'] += 1
                                        display_name = src_zone if (src_zone and src_zone != "FutureUse") else "Private-Net"
                                        payload.update({
                                            "country": display_name,
                                            "iso_code": "ZON",
                                            "lat": 0.0,
                                            "lon": 0.0
                                        })
                                        log('debug', f"Traffic event (private): {src_ip} ({display_name}) -> {dst_host}:{dst_port}")
                                        stats['total_events_emitted'] += 1
                                        await sio.emit('threat_event', payload)

                            except IndexError as e:
                                log('warning', f"Failed to parse traffic log: {e}", log_line=log_line[:100])
                    
                    # --- THREAT LOG PROCESSING ---
                    elif THREAT_ENABLED and log_type == "THREAT":
                        #action = fields[27].lower() if len(fields) > 27 else ""
                        action = fields[30].lower() if len(fields) > 30 else ""
                        if any(keyword in action for keyword in ['block', 'drop', 'reset', 'deny']):
                            try:
                                stats['threat_logs_processed'] += 1
                                
                                raw_time = fields[6]  # Generate Time
                                src_ip = fields[7]
                                dst_ip = fields[8]
                                app_id = fields[14]
                                src_zone = fields[16]
                                dst_port = fields[25]
                                
                                # Threat-specific fields (based on official PA documentation)
                                threat_name = fields[32] if len(fields) > 32 else "Unknown"
                                
                                # Use field 30 for actual threat category (malware, spyware, exploit, etc.)
                                # Ignore URL categories (field 69) as they're for egress traffic, not ingress threats
                                if len(fields) > 69 and fields[69] and fields[69] not in ['any', '(NULL)', '', 'N/A', 'none']:
                                    threat_category = fields[69]
                                else:
                                    threat_category = "uncategorized"
                                
                                severity = fields[34] if len(fields) > 34 else "medium"
                                
                                raw_proto = fields[26].lower() if len(fields) > 26 else "6"
                                if raw_proto in PROTOCOL_MAP: 
                                    proto = PROTOCOL_MAP[raw_proto]
                                elif raw_proto.isdigit(): 
                                    proto = f"PROTO-{raw_proto}"
                                else: 
                                    proto = raw_proto.upper()

                                if ALLOWED_ZONES and src_zone not in ALLOWED_ZONES:
                                    log('debug', f"Filtered out zone: {src_zone} from {src_ip}")
                                    continue

                                event_color = get_color_for_threat(severity)

                                try: 
                                    clean_time = raw_time.split(' ')[1]
                                except: 
                                    clean_time = datetime.now().strftime("%H:%M:%S")

                                dst_host = await loop.run_in_executor(executor, resolve_hostname, dst_ip)

                                payload = {
                                    "log_type": "threat",
                                    "timestamp": clean_time,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "dst_host": dst_host,
                                    "dst_port": dst_port,
                                    "proto": proto,
                                    "app": app_id,
                                    "threat_name": threat_name,
                                    "threat_category": threat_category,
                                    "severity": severity,
                                    "color": event_color
                                }

                                if reader:
                                    try:
                                        stats['geoip_lookups'] += 1
                                        response = reader.city(src_ip)
                                        payload.update({
                                            "country": response.country.name,
                                            "iso_code": response.country.iso_code,
                                            "lat": response.location.latitude,
                                            "lon": response.location.longitude
                                        })
                                        log('info', f"🚨 THREAT: {threat_name} ({severity}) | {src_ip} ({response.country.name}) -> {dst_host}:{dst_port} | Category: {threat_category}")
                                        stats['total_events_emitted'] += 1
                                        await sio.emit('threat_event', payload)
                                    except (ValueError, geoip2.errors.AddressNotFoundError) as e:
                                        stats['geoip_failures'] += 1
                                        display_name = src_zone if (src_zone and src_zone != "FutureUse") else "Private-Net"
                                        payload.update({
                                            "country": display_name,
                                            "iso_code": "ZON",
                                            "lat": 0.0,
                                            "lon": 0.0
                                        })
                                        log('info', f"🚨 THREAT: {threat_name} ({severity}) | {src_ip} ({display_name}) -> {dst_host}:{dst_port}")
                                        stats['total_events_emitted'] += 1
                                        await sio.emit('threat_event', payload)

                            except IndexError as e:
                                log('warning', f"Failed to parse threat log: {e}", log_line=log_line[:100])
                                
            except Exception as e:
                log('error', f"Error processing log: {e}")
                
    except Exception as e:
        log('critical', f"Fatal error in syslog_listener: {e}")
        raise

@app.get("/")
async def index(request: Request):
    log('debug', f"Dashboard accessed from {request.client.host}")
    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_title": config['dashboard']['title'],
        "app_subtitle": config['dashboard']['subtitle'],
        "home_lat": config['home']['latitude'],
        "home_lon": config['home']['longitude'],
        "traffic_enabled": TRAFFIC_ENABLED,
        "threat_enabled": THREAT_ENABLED
    })

@app.on_event("startup")
async def startup_event():
    log('info', "🚀 Application starting up")
    log('info', f"Configuration loaded: {len(RULE_COLORS)} traffic rule colors, {len(THREAT_COLORS)} threat severity colors")
    asyncio.create_task(syslog_listener())

@app.on_event("shutdown")
async def shutdown_event():
    log_statistics()  # Final stats dump
    log('info', "🛑 Application shutting down")

if __name__ == "__main__":
    use_ssl = config['server'].get('ssl_enabled', False)
    if use_ssl:
        log('info', f"🔒 Starting Secure Server on https://{config['server']['host']}:{config['server']['web_port']}")
        print(f"🔒 Starting Secure Server on https://{config['server']['host']}:{config['server']['web_port']}")
        uvicorn.run(socket_app, host=config['server']['host'], port=config['server']['web_port'], 
                    ssl_keyfile=config['server']['ssl_key'], ssl_certfile=config['server']['ssl_cert'])
    else:
        log('info', f"🔓 Starting HTTP Server on http://{config['server']['host']}:{config['server']['web_port']}")
        print(f"🔓 Starting HTTP Server on http://{config['server']['host']}:{config['server']['web_port']}")
        uvicorn.run(socket_app, host=config['server']['host'], port=config['server']['web_port'])
