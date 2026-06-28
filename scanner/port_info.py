SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "HTTP-Alt",
}

PORT_INFO: dict[int, dict[str, str]] = {
    21: {
        "description": "File Transfer Protocol (FTP) sends files between computers in plain text. Usernames and passwords are not encrypted unless FTPS is used.",
        "common_use": "Legacy file uploads and shared hosting",
        "risk": "High on untrusted networks — credentials and data can be intercepted",
    },
    22: {
        "description": "Secure Shell (SSH) provides encrypted remote login and command execution on servers and devices.",
        "common_use": "Remote administration of Linux servers, routers, and Raspberry Pi devices",
        "risk": "Medium — secure when patched, but a common brute-force target if exposed to the internet",
    },
    23: {
        "description": "Telnet offers remote terminal access with no encryption. Everything, including passwords, travels in plain text.",
        "common_use": "Legacy network equipment management",
        "risk": "High — should be disabled in favor of SSH",
    },
    25: {
        "description": "Simple Mail Transfer Protocol (SMTP) is used to send email between mail servers and clients.",
        "common_use": "Outbound mail delivery",
        "risk": "Medium — open relays can be abused for spam",
    },
    53: {
        "description": "Domain Name System (DNS) translates hostnames into IP addresses. Can use TCP for large responses or zone transfers.",
        "common_use": "Local DNS servers, routers, and Pi-hole",
        "risk": "Low to medium — misconfigured servers can be used in amplification attacks",
    },
    80: {
        "description": "Hypertext Transfer Protocol (HTTP) serves unencrypted web pages and APIs.",
        "common_use": "Websites, router admin pages, and IoT web interfaces",
        "risk": "Medium — traffic can be read or modified on untrusted networks",
    },
    110: {
        "description": "Post Office Protocol version 3 (POP3) downloads email from a server to a client, usually without encryption on this port.",
        "common_use": "Legacy email retrieval",
        "risk": "High without TLS — credentials and messages can be intercepted",
    },
    111: {
        "description": "Sun RPC portmapper helps clients find RPC services on a host.",
        "common_use": "NFS and other Unix RPC services",
        "risk": "Medium — can reveal services and aid exploitation on exposed systems",
    },
    135: {
        "description": "Microsoft RPC Endpoint Mapper lets Windows clients locate RPC services.",
        "common_use": "Windows networking and remote management",
        "risk": "Medium on Windows hosts — often seen with SMB services",
    },
    139: {
        "description": "NetBIOS Session Service supports legacy Windows file and printer sharing.",
        "common_use": "Older Windows network browsing and SMB over NetBIOS",
        "risk": "Medium to high — associated with Windows sharing and lateral movement",
    },
    143: {
        "description": "Internet Message Access Protocol (IMAP) lets email clients read mail stored on a server.",
        "common_use": "Mailbox access on mail servers",
        "risk": "High without TLS — sensitive mailbox data can be intercepted",
    },
    443: {
        "description": "HTTP Secure (HTTPS) encrypts web traffic with TLS. This is the standard port for secure websites and APIs.",
        "common_use": "Secure websites, web apps, and cloud services",
        "risk": "Low for transport security — still review what service is running",
    },
    445: {
        "description": "Server Message Block (SMB) provides Windows file sharing, printer sharing, and remote administration.",
        "common_use": "Windows file shares and Active Directory services",
        "risk": "High if exposed — frequent target for ransomware and credential attacks",
    },
    993: {
        "description": "IMAP over TLS (IMAPS) provides encrypted mailbox access.",
        "common_use": "Secure email retrieval",
        "risk": "Low for transport — depends on mail server configuration",
    },
    995: {
        "description": "POP3 over TLS (POP3S) provides encrypted email download.",
        "common_use": "Secure legacy email retrieval",
        "risk": "Low for transport — depends on mail server configuration",
    },
    1433: {
        "description": "Microsoft SQL Server listens here by default for database connections.",
        "common_use": "Enterprise applications and Windows-backed databases",
        "risk": "High if exposed — databases contain sensitive data and are attack targets",
    },
    1521: {
        "description": "Oracle Database commonly uses this port for client connections.",
        "common_use": "Enterprise Oracle database services",
        "risk": "High if exposed — privileged data store",
    },
    2049: {
        "description": "Network File System (NFS) shares directories over the network, common on Linux and NAS devices.",
        "common_use": "Shared storage on Linux servers and NAS boxes",
        "risk": "High if misconfigured — can expose entire filesystems",
    },
    3306: {
        "description": "MySQL and MariaDB use this port for database client connections.",
        "common_use": "Web apps, WordPress backends, and local development databases",
        "risk": "High if exposed — often targeted by automated database attacks",
    },
    3389: {
        "description": "Remote Desktop Protocol (RDP) provides graphical remote access to Windows systems.",
        "common_use": "Remote Windows desktop administration",
        "risk": "High if exposed — common target for credential stuffing and exploits",
    },
    5432: {
        "description": "PostgreSQL uses this port for database client connections.",
        "common_use": "Web applications and analytics databases",
        "risk": "High if exposed — contains application and user data",
    },
    5900: {
        "description": "Virtual Network Computing (VNC) shares a remote desktop screen and input.",
        "common_use": "Remote GUI access to Linux desktops and embedded systems",
        "risk": "High — often weakly authenticated and not encrypted by default",
    },
    6379: {
        "description": "Redis is an in-memory data store used for caching, queues, and sessions.",
        "common_use": "Application caching and pub/sub messaging",
        "risk": "Critical if exposed — often has no auth by default and can lead to full compromise",
    },
    8000: {
        "description": "Commonly used as an alternate HTTP port for development servers and web apps.",
        "common_use": "Python/Django dev servers, APIs, and custom web services",
        "risk": "Medium — may expose development or admin interfaces",
    },
    8080: {
        "description": "A popular alternate HTTP port for proxies, application servers, and admin consoles.",
        "common_use": "Tomcat, Jenkins, proxy servers, and router management",
        "risk": "Medium — frequently hosts admin panels or dev services",
    },
    8443: {
        "description": "Alternate HTTPS port often used when port 443 is already in use or for admin consoles.",
        "common_use": "Secure web admin interfaces and alternate TLS services",
        "risk": "Medium — review whether it exposes management functionality",
    },
    8888: {
        "description": "Another common alternate HTTP port for web interfaces and development tools.",
        "common_use": "Jupyter, some routers, and custom web dashboards",
        "risk": "Medium — may expose notebooks or admin tools",
    },
    9000: {
        "description": "Used by several services including PHP-FPM, SonarQube, and some IoT web panels.",
        "common_use": "Application services and admin dashboards",
        "risk": "Medium — depends on the specific service bound to the port",
    },
}


def get_port_info(port: int) -> dict:
    service = SERVICE_NAMES.get(port, "unknown")
    info = PORT_INFO.get(port)

    if info:
        return {
            "port": port,
            "service": service,
            "description": info["description"],
            "common_use": info["common_use"],
            "risk": info["risk"],
        }

    if 1 <= port <= 1023:
        category = "well-known port"
    elif 1024 <= port <= 49151:
        category = "registered port"
    else:
        category = "dynamic/private port"

    return {
        "port": port,
        "service": service,
        "description": (
            f"Port {port} is a {category}. It may be assigned to a specific application, "
            "used by a custom service, or opened temporarily by an application."
        ),
        "common_use": "Varies by installed software and configuration",
        "risk": "Review the service bound to this port before exposing it beyond your local network",
    }
