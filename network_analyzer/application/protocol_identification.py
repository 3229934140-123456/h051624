"""
应用层协议识别
===============
基于端口号和数据特征识别应用层协议。

识别策略:
1. 基于知名端口号 (Port-based)
   - TCP 80 -> HTTP
   - TCP 443 -> HTTPS
   - TCP 21 -> FTP
   - TCP 22 -> SSH
   - TCP 25 -> SMTP
   - TCP 110 -> POP3
   - TCP 143 -> IMAP
   - TCP 23 -> Telnet
   - TCP 3389 -> RDP
   - UDP 53 -> DNS
   - TCP 53 -> DNS
   - UDP 67/68 -> DHCP
   - etc.

2. 基于数据特征 (Signature-based / Deep Packet Inspection)
   - HTTP: 以"GET /", "POST /", "HTTP/1.", "HEAD ", etc. 开头
   - TLS/SSL: 以\x16\x03\x01 (ClientHello) 开头
   - SSH: 以"SSH-"开头
   - FTP: 包含"220 ", "USER ", "PASS "等命令
   - DNS: 特定的报文格式
   - SMTP: "220 ", "EHLO ", "MAIL FROM:" 等

3. 启发式识别
   - 结合端口和数据特征进行综合判断
   - 多包分析，观察交互模式

协议识别状态:
- UNKNOWN: 未识别
- PORT_BASED: 基于端口识别
- SIGNATURE_BASED: 基于数据特征识别
- CONFIRMED: 多包确认
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, List
from enum import Enum


class AppProtocol(str, Enum):
    """应用层协议枚举"""
    UNKNOWN = "unknown"
    HTTP = "http"
    HTTPS = "https"
    TLS = "tls"
    FTP = "ftp"
    SSH = "ssh"
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"
    DNS = "dns"
    DHCP = "dhcp"
    TELNET = "telnet"
    RDP = "rdp"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    REDIS = "redis"
    MQTT = "mqtt"
    SIP = "sip"
    RTSP = "rtsp"
    SMB = "smb"
    RTP = "rtp"
    NTP = "ntp"
    SNMP = "snmp"


class IdentificationMethod(str, Enum):
    """识别方法"""
    UNKNOWN = "unknown"
    PORT_BASED = "port_based"
    SIGNATURE_BASED = "signature_based"
    CONFIRMED = "confirmed"


WELL_KNOWN_PORTS_TCP = {
    21: AppProtocol.FTP,
    22: AppProtocol.SSH,
    23: AppProtocol.TELNET,
    25: AppProtocol.SMTP,
    53: AppProtocol.DNS,
    80: AppProtocol.HTTP,
    110: AppProtocol.POP3,
    143: AppProtocol.IMAP,
    443: AppProtocol.HTTPS,
    465: AppProtocol.SMTP,
    993: AppProtocol.IMAP,
    995: AppProtocol.POP3,
    3306: AppProtocol.MYSQL,
    3389: AppProtocol.RDP,
    5432: AppProtocol.POSTGRES,
    6379: AppProtocol.REDIS,
    8080: AppProtocol.HTTP,
    8443: AppProtocol.HTTPS,
    1883: AppProtocol.MQTT,
    5060: AppProtocol.SIP,
    554: AppProtocol.RTSP,
    445: AppProtocol.SMB,
    139: AppProtocol.SMB,
}

WELL_KNOWN_PORTS_UDP = {
    53: AppProtocol.DNS,
    67: AppProtocol.DHCP,
    68: AppProtocol.DHCP,
    69: AppProtocol.FTP,
    5060: AppProtocol.SIP,
    5004: AppProtocol.RTP,
    5005: AppProtocol.RTP,
    123: AppProtocol.NTP,
    161: AppProtocol.SNMP,
    162: AppProtocol.SNMP,
}


HTTP_METHODS = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
]

HTTP_RESPONSE_PREFIX = b"HTTP/1."

TLS_HANDSHAKE_TYPE = 0x16
TLS_VERSIONS = [
    b"\x03\x00",
    b"\x03\x01",
    b"\x03\x02",
    b"\x03\x03",
    b"\x03\x04",
]

SSH_PREFIX = b"SSH-"

FTP_COMMANDS = [
    b"USER ",
    b"PASS ",
    b"LIST",
    b"RETR ",
    b"STOR ",
    b"QUIT",
    b"PASV",
    b"PORT ",
    b"SYST",
    b"TYPE ",
]

FTP_RESPONSES = [
    b"220 ",
    b"230 ",
    b"331 ",
    b"530 ",
    b"150 ",
    b"226 ",
    b"221 ",
]

SMTP_COMMANDS = [
    b"EHLO ",
    b"HELO ",
    b"MAIL FROM:",
    b"RCPT TO:",
    b"DATA",
    b"QUIT",
    b"RSET",
    b"NOOP",
]

SMTP_RESPONSES = [
    b"220 ",
    b"250 ",
    b"221 ",
    b"354 ",
    b"550 ",
]

POP3_COMMANDS = [
    b"USER ",
    b"PASS ",
    b"LIST",
    b"RETR ",
    b"DELE ",
    b"QUIT",
    b"STAT",
    b"TOP ",
]

POP3_RESPONSES = [
    b"+OK ",
    b"-ERR ",
    b"+OK\r\n",
]

IMAP_COMMANDS = [
    b" LOGIN ",
    b" SELECT ",
    b" FETCH ",
    b" STORE ",
    b" EXPUNGE",
    b" LOGOUT",
    b" LIST ",
    b" STATUS ",
]

IMAP_RESPONSES = [
    b"* OK ",
    b"* BAD ",
    b"* NO ",
    b" OK ",
    b" BAD ",
    b" NO ",
]

DNS_HEADER_SIZE = 12

REDIS_COMMANDS = [
    b"*",
    b"PING",
    b"SET ",
    b"GET ",
    b"INCR",
    b"DECR",
    b"DEL ",
    b"EXISTS ",
    b"KEYS ",
]

MQTT_PACKET_TYPES = [
    0x10,
    0x20,
    0x30,
    0x40,
    0x50,
    0x60,
    0x70,
    0x80,
    0x90,
    0xA0,
    0xB0,
    0xC0,
    0xD0,
    0xE0,
]

MYSQL_SIGNATURES = [
    b"\x0a",
]

POSTGRES_SIGNATURES = [
    b"\x00\x03\x00\x00",
]


@dataclass
class ProtocolIdentificationResult:
    """协议识别结果"""
    protocol: AppProtocol = AppProtocol.UNKNOWN
    method: IdentificationMethod = IdentificationMethod.UNKNOWN
    confidence: float = 0.0
    details: Dict = field(default_factory=dict)
    
    def __str__(self) -> str:
        return f"{self.protocol.value} ({self.method.value}, confidence={self.confidence:.2f})"


class AppProtocolIdentifier:
    """
    应用层协议识别器
    
    综合使用端口号和数据特征进行应用协议识别。
    
    使用方法:
        identifier = AppProtocolIdentifier()
        result = identifier.identify(data, src_port, dst_port, is_tcp=True)
    """
    
    def __init__(self):
        self._connections: Dict[Tuple, ProtocolIdentificationResult] = {}
        self._signature_checks = [
            ("http", self._check_http),
            ("tls", self._check_tls),
            ("ssh", self._check_ssh),
            ("ftp", self._check_ftp),
            ("smtp", self._check_smtp),
            ("pop3", self._check_pop3),
            ("imap", self._check_imap),
            ("dns", self._check_dns),
            ("redis", self._check_redis),
            ("mqtt", self._check_mqtt),
            ("mysql", self._check_mysql),
            ("postgres", self._check_postgres),
        ]
    
    def identify(
        self,
        data: bytes,
        src_port: int,
        dst_port: int,
        is_tcp: bool = True,
        connection_key: Optional[Tuple] = None,
    ) -> ProtocolIdentificationResult:
        """
        识别应用层协议
        
        Args:
            data: 应用层数据
            src_port: 源端口
            dst_port: 目的端口
            is_tcp: 是否是TCP协议
            connection_key: 连接键(用于跟踪连接级别的识别状态)
        
        Returns:
            ProtocolIdentificationResult: 识别结果
        """
        prev_result = None
        if connection_key and connection_key in self._connections:
            prev_result = self._connections[connection_key]
        
        if prev_result and prev_result.method == IdentificationMethod.CONFIRMED:
            return prev_result
        
        port_result = self._identify_by_port(src_port, dst_port, is_tcp)
        
        sig_result = self._identify_by_signature(data, is_tcp)
        
        result = self._merge_results(port_result, sig_result, prev_result)
        
        if connection_key:
            if result.confidence > 0.8:
                result.method = IdentificationMethod.CONFIRMED
            self._connections[connection_key] = result
        
        return result
    
    def _identify_by_port(
        self,
        src_port: int,
        dst_port: int,
        is_tcp: bool
    ) -> ProtocolIdentificationResult:
        """基于端口号识别协议"""
        port_map = WELL_KNOWN_PORTS_TCP if is_tcp else WELL_KNOWN_PORTS_UDP
        
        protocol = port_map.get(dst_port) or port_map.get(src_port)
        
        if protocol and isinstance(protocol, AppProtocol):
            return ProtocolIdentificationResult(
                protocol=protocol,
                method=IdentificationMethod.PORT_BASED,
                confidence=0.5,
                details={"port": dst_port if dst_port in port_map else src_port}
            )
        
        return ProtocolIdentificationResult(
            protocol=AppProtocol.UNKNOWN,
            method=IdentificationMethod.PORT_BASED,
            confidence=0.0
        )
    
    def _identify_by_signature(
        self,
        data: bytes,
        is_tcp: bool
    ) -> ProtocolIdentificationResult:
        """基于数据特征识别协议"""
        if not data:
            return ProtocolIdentificationResult(
                protocol=AppProtocol.UNKNOWN,
                method=IdentificationMethod.SIGNATURE_BASED,
                confidence=0.0
            )
        
        best_result = ProtocolIdentificationResult(
            protocol=AppProtocol.UNKNOWN,
            method=IdentificationMethod.SIGNATURE_BASED,
            confidence=0.0
        )
        
        for name, check_func in self._signature_checks:
            try:
                match, confidence, details = check_func(data)
                if match and confidence > best_result.confidence:
                    proto = AppProtocol(name)
                    best_result = ProtocolIdentificationResult(
                        protocol=proto,
                        method=IdentificationMethod.SIGNATURE_BASED,
                        confidence=confidence,
                        details=details
                    )
            except Exception:
                continue
        
        return best_result
    
    def _merge_results(
        self,
        port_result: ProtocolIdentificationResult,
        sig_result: ProtocolIdentificationResult,
        prev_result: Optional[ProtocolIdentificationResult] = None
    ) -> ProtocolIdentificationResult:
        """合并多种识别方法的结果"""
        if sig_result.protocol != AppProtocol.UNKNOWN:
            if port_result.protocol == sig_result.protocol:
                merged = ProtocolIdentificationResult(
                    protocol=sig_result.protocol,
                    method=IdentificationMethod.CONFIRMED,
                    confidence=min(1.0, sig_result.confidence + 0.2),
                    details={**sig_result.details, "port_match": True}
                )
            else:
                merged = ProtocolIdentificationResult(
                    protocol=sig_result.protocol,
                    method=IdentificationMethod.SIGNATURE_BASED,
                    confidence=sig_result.confidence,
                    details=sig_result.details
                )
        elif port_result.protocol != AppProtocol.UNKNOWN:
            merged = port_result
        else:
            merged = ProtocolIdentificationResult(
                protocol=AppProtocol.UNKNOWN,
                method=IdentificationMethod.UNKNOWN,
                confidence=0.0
            )
        
        if prev_result and prev_result.protocol == merged.protocol:
            merged.confidence = min(1.0, merged.confidence + 0.1)
            if merged.confidence > 0.8:
                merged.method = IdentificationMethod.CONFIRMED
        
        return merged
    
    def _check_http(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是HTTP协议"""
        details = {}
        
        for method in HTTP_METHODS:
            if data.startswith(method):
                details["method"] = method.decode("ascii", errors="replace").strip()
                details["type"] = "request"
                return True, 0.9, details
        
        if data.startswith(HTTP_RESPONSE_PREFIX):
            if len(data) >= 12 and data[8:9] == b" ":
                try:
                    status_code = int(data[9:12])
                    details["status_code"] = status_code
                except ValueError:
                    pass
            details["type"] = "response"
            return True, 0.9, details
        
        if b"Host: " in data[:512] and b"\r\n\r\n" in data[:2048]:
            details["type"] = "header_detected"
            return True, 0.6, details
        
        return False, 0.0, details
    
    def _check_tls(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是TLS/SSL协议"""
        details = {}
        
        if len(data) < 5:
            return False, 0.0, details
        
        content_type = data[0]
        version = data[1:3]
        length = int.from_bytes(data[3:5], "big")
        
        if content_type == TLS_HANDSHAKE_TYPE and version in TLS_VERSIONS:
            if len(data) >= 5 + length or length > 0:
                details["version"] = version.hex()
                details["type"] = "handshake"
                details["length"] = length
                
                if len(data) >= 6:
                    handshake_type = data[5]
                    if handshake_type == 0x01:
                        details["handshake_type"] = "ClientHello"
                        return True, 0.95, details
                    elif handshake_type == 0x02:
                        details["handshake_type"] = "ServerHello"
                        return True, 0.95, details
                    else:
                        details["handshake_type"] = f"0x{handshake_type:02x}"
                        return True, 0.8, details
                
                return True, 0.7, details
        
        return False, 0.0, details
    
    def _check_ssh(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是SSH协议"""
        details = {}
        
        if data.startswith(SSH_PREFIX):
            line_end = data.find(b"\r\n")
            if line_end == -1:
                line_end = data.find(b"\n")
            
            if line_end > 0:
                version_str = data[4:line_end].decode("ascii", errors="replace")
                details["version"] = version_str
                return True, 0.9, details
            else:
                return True, 0.7, details
        
        return False, 0.0, details
    
    def _check_ftp(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是FTP协议"""
        details = {}
        
        for cmd in FTP_COMMANDS:
            if data.startswith(cmd):
                details["command"] = cmd.decode("ascii", errors="replace").strip()
                details["type"] = "command"
                return True, 0.8, details
        
        for resp in FTP_RESPONSES:
            if data.startswith(resp):
                details["response"] = resp.decode("ascii", errors="replace").strip()
                details["type"] = "response"
                return True, 0.8, details
        
        return False, 0.0, details
    
    def _check_smtp(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是SMTP协议"""
        details = {}
        
        for cmd in SMTP_COMMANDS:
            if data.startswith(cmd):
                details["command"] = cmd.decode("ascii", errors="replace").strip()
                return True, 0.85, details
        
        for resp in SMTP_RESPONSES:
            if data.startswith(resp):
                try:
                    code = int(data[:3])
                    details["response_code"] = code
                    return True, 0.85, details
                except ValueError:
                    pass
        
        return False, 0.0, details
    
    def _check_pop3(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是POP3协议"""
        details = {}
        
        for cmd in POP3_COMMANDS:
            if data.startswith(cmd):
                details["command"] = cmd.decode("ascii", errors="replace").strip()
                return True, 0.8, details
        
        for resp in POP3_RESPONSES:
            if data.startswith(resp):
                details["response"] = resp.decode("ascii", errors="replace").strip()
                return True, 0.8, details
        
        return False, 0.0, details
    
    def _check_imap(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是IMAP协议"""
        details = {}
        
        for cmd in IMAP_COMMANDS:
            if cmd in data[:512]:
                details["command_matched"] = True
                return True, 0.7, details
        
        for resp in IMAP_RESPONSES:
            if data.startswith(resp) or resp in data[:256]:
                details["response_matched"] = True
                return True, 0.7, details
        
        return False, 0.0, details
    
    def _check_dns(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是DNS协议"""
        details = {}
        
        if len(data) < DNS_HEADER_SIZE:
            return False, 0.0, details
        
        flags = int.from_bytes(data[2:4], "big")
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        qdcount = int.from_bytes(data[4:6], "big")
        ancount = int.from_bytes(data[6:8], "big")
        
        if qdcount <= 100 and ancount <= 100 and opcode <= 5:
            details["is_response"] = bool(qr)
            details["opcode"] = opcode
            details["questions"] = qdcount
            details["answers"] = ancount
            return True, 0.6, details
        
        return False, 0.0, details
    
    def _check_redis(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是Redis协议"""
        details = {}
        
        if data.startswith(b"+") or data.startswith(b"-") or data.startswith(b":"):
            return True, 0.6, details
        
        if data.startswith(b"$"):
            return True, 0.7, details
        
        if data.startswith(b"*"):
            try:
                line_end = data.find(b"\r\n")
                if line_end > 0:
                    count = int(data[1:line_end])
                    if 0 < count < 100:
                        details["command_count"] = count
                        return True, 0.8, details
            except ValueError:
                pass
        
        for cmd in REDIS_COMMANDS[1:5]:
            if data.upper().startswith(cmd):
                details["command"] = cmd.decode("ascii", errors="replace").strip()
                return True, 0.7, details
        
        return False, 0.0, details
    
    def _check_mqtt(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是MQTT协议"""
        details = {}
        
        if not data:
            return False, 0.0, details
        
        packet_type = data[0] & 0xF0
        
        if packet_type in MQTT_PACKET_TYPES:
            remaining_length = 0
            multiplier = 1
            offset = 1
            
            while offset < len(data) and offset <= 4:
                byte = data[offset]
                remaining_length += (byte & 0x7F) * multiplier
                if (byte & 0x80) == 0:
                    break
                multiplier *= 128
                offset += 1
            
            if remaining_length < 65536:
                details["packet_type"] = f"0x{packet_type:02x}"
                details["remaining_length"] = remaining_length
                return True, 0.6, details
        
        return False, 0.0, details
    
    def _check_mysql(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是MySQL协议"""
        details = {}
        
        if len(data) < 5:
            return False, 0.0, details
        
        pkt_len = int.from_bytes(data[:3], "little")
        pkt_seq = data[3]
        
        if pkt_len == 0 or pkt_len > 16777216:
            return False, 0.0, details
        
        if pkt_seq == 0 and (data[4] == 0x0a or data[4] == 0x09):
            details["type"] = "greeting"
            details["protocol_version"] = data[4]
            return True, 0.7, details
        
        if pkt_seq == 1 and data[4] in (0x03, 0x02):
            details["type"] = "handshake_response"
            return True, 0.6, details
        
        return False, 0.0, details
    
    def _check_postgres(self, data: bytes) -> Tuple[bool, float, Dict]:
        """检查是否是PostgreSQL协议"""
        details = {}
        
        if len(data) >= 8 and data.startswith(b"\x00\x03\x00\x00"):
            details["type"] = "startup"
            return True, 0.8, details
        
        if len(data) >= 5:
            msg_type = data[0:1]
            msg_len = int.from_bytes(data[1:5], "big")
            
            if msg_len > 4 and msg_len < 65536:
                if msg_type in [b"Q", b"P", b"B", b"E", b"D", b"S", b"X", b"R", b"Z", b"T", b"C"]:
                    details["message_type"] = msg_type.decode("ascii", errors="replace")
                    details["message_length"] = msg_len
                    return True, 0.7, details
        
        return False, 0.0, details
    
    def reset(self):
        """重置识别器"""
        self._connections.clear()


def identify_protocol(
    data: bytes,
    src_port: int,
    dst_port: int,
    is_tcp: bool = True
) -> AppProtocol:
    """
    便捷函数：快速识别应用层协议
    
    Args:
        data: 应用层数据
        src_port: 源端口
        dst_port: 目的端口
        is_tcp: 是否是TCP协议
    
    Returns:
        AppProtocol: 识别出的协议
    """
    identifier = AppProtocolIdentifier()
    result = identifier.identify(data, src_port, dst_port, is_tcp)
    return result.protocol
