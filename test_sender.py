import socket
import time
import random
from datetime import datetime

UDP_IP = "127.0.0.1"
UDP_PORT = 514

# Test data pools - Diverse public IPs from around the world for GeoIP testing
PUBLIC_IPS = [
    "8.8.8.8",          # Google DNS - USA
    "1.1.1.1",          # Cloudflare - USA
    "45.33.32.156",     # Linode - USA
    "185.199.108.153",  # GitHub - USA
    "80.82.77.139",     # UK
    "195.154.122.113",  # France
    "212.183.159.230",  # Germany
    "91.108.56.100",    # Russia
    "202.12.27.33",     # China
    "210.140.92.142",   # Japan
    "203.133.1.6",      # South Korea
    "119.81.142.131",   # India
    "200.221.11.100",   # Brazil
    "41.217.196.27",    # South Africa
    "103.28.38.224",    # Australia
    "165.227.47.218",   # Singapore
    "103.21.244.8",     # Philippines
    "190.104.218.142",  # Mexico
    "84.88.55.2",       # Netherlands
    "94.142.241.111",   # Turkey
]
PRIVATE_IPS = ["10.1.1.50", "192.168.100.75", "172.16.5.100"]
DST_IPS = ["10.50.100.25", "10.50.100.30", "10.50.100.35"]
APPS = ["web-browsing", "ssl", "dns", "ssh", "ftp", "ms-rdp"]
PORTS = ["80", "443", "53", "22", "21", "3389"]

# Traffic Log Rules
TRAFFIC_RULES = [
    "Default-Deny", "Geo-Block-Restricted", "Policy-Deny-External", 
    "Malware-Protection", "Spyware-Block", "Block-Legacy"
]

# Threat data based on real PA signatures
THREAT_DATA = [
    {"name": "Backdoor.Win32.Agent(12345)", "cat": "backdoor", "sev": "high"},
    {"name": "Trojan.Generic.KD(67890)", "cat": "malware", "sev": "critical"},
    {"name": "Adware.Tracking.Cookie(11111)", "cat": "adware", "sev": "low"},
    {"name": "Exploit.CVE-2021-44228(22222)", "cat": "exploit", "sev": "critical"},
    {"name": "Spyware.Keylogger.Generic(33333)", "cat": "spyware", "sev": "high"},
    {"name": "C2.Cobalt.Strike(44444)", "cat": "command-and-control", "sev": "critical"},
    {"name": "Ransomware.Lockbit.Variant(55555)", "cat": "ransomware", "sev": "critical"},
    {"name": "Phishing.Credential.Harvester(66666)", "cat": "phishing", "sev": "medium"},
    {"name": "Tunneling:malicious-dns(109001001)", "cat": "dns-c2", "sev": "high"},
    {"name": "SCAN: Host Sweep(8002)", "cat": "scan", "sev": "medium"},
    {"name": "HTTP SQL Injection Attempt(38531)", "cat": "sql-injection", "sev": "high"},
    {"name": "Suspicious File Download(77777)", "cat": "virus", "sev": "medium"},
    {"name": "Cryptomining Activity(88888)", "cat": "cryptomining", "sev": "medium"},
]

THREAT_TYPES = ["url", "file", "virus", "vulnerability", "wildfire"]
DIRECTIONS = ["client-to-server", "server-to-client"]
ACTIONS = ["drop", "reset-both", "block-url", "block"]

def generate_timestamp():
    """Generate current timestamp in PA format"""
    return datetime.now().strftime("%Y/%m/%d %H:%M:%S")

def generate_traffic_log():
    """Generates a PA-OS TRAFFIC log with deny/drop action"""
    src_ip = random.choice(PUBLIC_IPS) if random.random() > 0.4 else random.choice(PRIVATE_IPS)
    src_zone = "External-Untrust" if src_ip in PUBLIC_IPS else "VPN-Zone"
    dst_ip = random.choice(DST_IPS)
    app = random.choice(APPS)
    port = random.choice(PORTS)
    rule = random.choice(TRAFFIC_RULES)
    
    log_structure = [
        "1",                            # [0] FUTURE_USE
        generate_timestamp(),           # [1] Receive Time
        "012501000001",                 # [2] Serial Number
        "TRAFFIC",                      # [3] Type
        "end",                          # [4] Subtype
        "2048",                         # [5] FUTURE_USE
        generate_timestamp(),           # [6] Generated Time
        src_ip,                         # [7] Source Address
        dst_ip,                         # [8] Destination Address
        "0.0.0.0",                      # [9] NAT Source IP
        "0.0.0.0",                      # [10] NAT Destination IP
        rule,                           # [11] Rule Name
        "user@domain.local",            # [12] Source User
        "",                             # [13] Destination User
        app,                            # [14] Application
        "vsys1",                        # [15] Virtual System
        src_zone,                       # [16] Source Zone
        "Internal-Trust",               # [17] Destination Zone
        "ethernet1/1",                  # [18] Inbound Interface
        "ethernet1/2",                  # [19] Outbound Interface
        "Log-Forward",                  # [20] Log Action
        "0",                            # [21] FUTURE_USE
        str(random.randint(1000000, 9999999)),  # [22] Session ID
        "1",                            # [23] Repeat Count
        str(random.randint(1024, 65535)),  # [24] Source Port
        port,                           # [25] Destination Port
        "0",                            # [26] NAT Source Port
        "0",                            # [27] NAT Destination Port
        "0x0",                          # [28] Flags
        "6",                            # [29] IP Protocol (TCP)
        "deny",                         # [30] Action
        str(random.randint(100, 5000)), # [31] Bytes
        str(random.randint(100, 5000)), # [32] Bytes Sent
        str(random.randint(100, 5000)), # [33] Bytes Received
        str(random.randint(1, 100)),    # [34] Packets
        generate_timestamp(),           # [35] Start Time
        "0",                            # [36] Elapsed Time
        "business-systems",             # [37] URL Category
        "0",                            # [38] FUTURE_USE
        str(random.randint(1000000000, 9999999999)),  # [39] Sequence Number
        "0x0",                          # [40] Action Flags
        "US",                           # [41] Source Country
        "US",                           # [42] Destination Country
        "0",                            # [43] FUTURE_USE
        str(random.randint(1, 100)),    # [44] Packets Sent
        str(random.randint(1, 100)),    # [45] Packets Received
    ]
    return ",".join(log_structure)

def generate_threat_log():
    """
    Generates complete PA-OS THREAT log with all fields from official documentation
    Reference: https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields
    All field indices are 0-based as per PA documentation
    """
    # Always use public IPs for threat logs so GeoIP lookup succeeds
    src_ip = random.choice(PUBLIC_IPS)
    src_zone = "External-Untrust"
    dst_ip = random.choice(DST_IPS)
    app = random.choice(APPS)
    src_port = str(random.randint(1024, 65535))
    dst_port = random.choice(PORTS)
    
    # Select random threat
    threat = random.choice(THREAT_DATA)
    threat_type = random.choice(THREAT_TYPES)
    direction = random.choice(DIRECTIONS)
    action = random.choice(ACTIONS)
    
    # Generate realistic URLs with potential commas for CSV testing
    malicious_urls = [
        f"http://malware{random.randint(1,999)}.example.com/payload.exe?id=1,2,3",
        f"https://phishing-site.net/login?user=test&data=a,b,c",
        f"http://c2-domain.org/beacon?params=x,y,z",
        f"ftp://suspicious.host/file.zip?token=abc,def,ghi"
    ]
    misc_url = random.choice(malicious_urls)
    
    # Current timestamp
    ts = generate_timestamp()
    session_id = str(random.randint(10000000, 99999999))
    seq_num = str(random.randint(1000000000000000000, 9999999999999999999))
    
    # Complete PA-OS THREAT log structure (all 86 fields)
    log_structure = [
        # Fields 0-10: Basic metadata
        "1",                                    # [0] FUTURE_USE
        ts,                                     # [1] Receive Time
        "012501000001",                         # [2] Serial Number
        "THREAT",                               # [3] Type
        threat_type,                            # [4] Threat/Content Type (url, file, virus, vulnerability, wildfire)
        "2562",                                 # [5] Config Version
        ts,                                     # [6] Generated Time
        src_ip,                                 # [7] Source Address
        dst_ip,                                 # [8] Destination Address
        "0.0.0.0",                              # [9] NAT Source IP
        "0.0.0.0",                              # [10] NAT Destination IP
        
        # Fields 11-20: Policy and routing
        "Default-Ingress-Rule",                 # [11] Rule Name
        "user@domain.local",                    # [12] Source User
        "",                                     # [13] Destination User
        app,                                    # [14] Application
        "vsys1",                                # [15] Virtual System
        src_zone,                               # [16] Source Zone
        "Internal-Trust",                       # [17] Destination Zone
        "ethernet1/1",                          # [18] Inbound Interface
        "ethernet1/2",                          # [19] Outbound Interface
        "Log-Forward",                          # [20] Log Action
        
        # Fields 21-28: Session info
        "0",                                    # [21] FUTURE_USE
        session_id,                             # [22] Session ID
        "1",                                    # [23] Repeat Count
        src_port,                               # [24] Source Port
        dst_port,                               # [25] Destination Port
        "0",                                    # [26] NAT Source Port
        "0",                                    # [27] NAT Destination Port
        "0x0",                                  # [28] Flags
        
        # Fields 29-31: Protocol and action
        "6",                                    # [29] IP Protocol (6=TCP)
        action,                                 # [30] Action (drop, reset-both, block-url, block)
        f'"{misc_url}"',                        # [31] Miscellaneous/URL (quoted to handle commas)
        
        # Fields 32-36: Threat details
        threat["name"],                         # [32] Threat/Content Name
        "any",                                  # [33] Category (placeholder - often 'any')
        threat["sev"],                          # [34] Severity (critical, high, medium, low, informational)
        direction,                              # [35] Direction (client-to-server, server-to-client)
        seq_num,                                # [36] Sequence Number
        
        # Fields 37-42: Action and location
        "0x8000000000000000",                   # [37] Action Flags
        "United States",                        # [38] Source Country
        "United States",                        # [39] Destination Country
        "0",                                    # [40] FUTURE_USE
        "application/octet-stream",             # [41] Content Type
        "0",                                    # [42] PCAP_ID
        
        # Fields 43-48: File details
        "",                                     # [43] File Digest (SHA-256 for files)
        "",                                     # [44] Cloud Address
        "0",                                    # [45] URL Index
        "HTTP",                                 # [46] User Agent
        "text/html",                            # [47] File Type
        "firefox",                              # [48] X-Forwarded-For
        
        # Fields 49-53: HTTP details
        "HTTP/1.1",                             # [49] Referer
        "user@sender.com",                      # [50] Sender (email)
        "user@recipient.com",                   # [51] Subject (email)
        "user@recipient.com",                   # [52] Recipient (email)
        "Report XYZ",                           # [53] Report ID
        
        # Fields 54-58: Device and user
        "DeviceGroupA",                         # [54] Device Group Hierarchy Level 1
        "DeviceGroupB",                         # [55] Device Group Hierarchy Level 2
        "DeviceGroupC",                         # [56] Device Group Hierarchy Level 3
        "DeviceGroupD",                         # [57] Device Group Hierarchy Level 4
        "vsys1",                                # [58] Virtual System Name
        
        # Fields 59-62: Source device
        "Laptop-001",                           # [59] Device Name (Source)
        "Windows",                              # [60] Source OS
        "10.21",                                # [61] Source OS Version
        "laptop",                               # [62] Source Host
        
        # Fields 63-66: Destination device
        "Server-001",                           # [63] Device Name (Destination)
        "Linux",                                # [64] Destination OS
        "Ubuntu 20.04",                         # [65] Destination OS Version
        "webserver",                            # [66] Destination Host
        
        # Fields 67-69: Container and category
        "container-01",                         # [67] Container ID
        "pod-web-01",                           # [68] POD Namespace
        threat["cat"],                          # [69] Threat Category *** THIS IS THE KEY FIELD ***
        
        # Fields 70-74: Additional metadata
        "medium",                               # [70] Content Version
        "",                                     # [71] SIG Flags (signature flags)
        "0",                                    # [72] FUTURE_USE
        "Standard",                             # [73] Source Dynamic Address Group
        "Servers",                              # [74] Destination Dynamic Address Group
        
        # Fields 75-79: EDR and correlation
        "",                                     # [75] Partial Hash (SHA-1 for WildFire)
        "monitor",                              # [76] Cortex Data Lake Tenant ID
        "benign",                               # [77] Inline ML Verdict
        "Workstation",                          # [78] Source Device Category
        "Server",                               # [79] Destination Device Category
        
        # Fields 80-85: Profiles and UUID
        "DefaultProfile",                       # [80] Source Device Profile
        "ServerProfile",                        # [81] Destination Device Profile
        "Corp-Model-A",                         # [82] Source Device Model
        "Datacenter-Model-B",                   # [83] Destination Device Model
        "Acme-Corp",                            # [84] Source Device Vendor
        "Enterprise-Systems",                   # [85] Destination Device Vendor
    ]
    
    return ",".join(log_structure)

def main():
    print(f"🚀 Enhanced PA-OS Syslog Test Generator")
    print(f"📡 Target: {UDP_IP}:{UDP_PORT}")
    print(f"📊 Generating TRAFFIC and THREAT logs with complete field sets")
    print(f"⚠️  Toggle dashboard modes to see different views\n")
    print(f"🔍 THREAT logs now include all 86 fields per PA documentation")
    print(f"   Field [69] = Threat Category (the key field for Layer 7 view)\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        counter = 0
        traffic_count = 0
        threat_count = 0
        
        while True:
            # Generate more threats than traffic for better Layer 7 testing
            if random.random() < 0.3:  # 30% traffic, 70% threat
                log = generate_traffic_log()
                log_type = "TRAFFIC"
                traffic_count += 1
            else:
                log = generate_threat_log()
                log_type = "THREAT"
                threat_count += 1
            
            sock.sendto(log.encode(), (UDP_IP, UDP_PORT))
            counter += 1
            
            if counter % 10 == 0:
                print(f"✅ Sent {counter} total | Traffic: {traffic_count} | Threats: {threat_count}")
            
            time.sleep(0.4)  # Slightly faster for more threat events
            
    except KeyboardInterrupt:
        print(f"\n🛑 Stopped after {counter} total logs")
        print(f"   📊 Traffic: {traffic_count} | Threats: {threat_count}")

if __name__ == "__main__":
    main()