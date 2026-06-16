"""
网络层解析 - IPv4
==================
解析IPv4数据包，提取IP头各字段，识别分片信息。

IPv4头格式:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP分片:
- MF标志位 (More Fragments): 1表示后续还有分片，0表示最后一个分片
- 分片偏移 (Fragment Offset): 13位，以8字节为单位
- 一个数据报的所有分片具有相同的Identification字段
- 只有第一个分片包含传输层头
"""

import struct
import socket
from dataclasses import dataclass, field
from typing import Optional, List


IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMPv6 = 58

IP_MIN_HEADER_LEN = 20
IP_MAX_HEADER_LEN = 60

IP_FLAG_DF = 0x4000
IP_FLAG_MF = 0x2000
IP_FRAGMENT_MASK = 0x1FFF


@dataclass
class IPHeader:
    """IPv4头部信息"""
    version: int = 4
    ihl: int = 5
    ihl_bytes: int = 20
    tos: int = 0
    total_length: int = 0
    identification: int = 0
    flags: int = 0
    fragment_offset: int = 0
    ttl: int = 0
    protocol: int = 0
    header_checksum: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    options: bytes = b""
    
    @property
    def df_flag(self) -> bool:
        """Don't Fragment标志"""
        return bool((self.flags >> 1) & 0x01)
    
    @property
    def mf_flag(self) -> bool:
        """More Fragments标志"""
        return bool(self.flags & 0x01)
    
    @property
    def is_fragmented(self) -> bool:
        """是否是分片数据包"""
        return self.fragment_offset > 0 or self.mf_flag
    
    @property
    def is_first_fragment(self) -> bool:
        """是否是第一个分片"""
        return self.fragment_offset == 0
    
    @property
    def is_last_fragment(self) -> bool:
        """是否是最后一个分片"""
        return not self.mf_flag
    
    @property
    def fragment_offset_bytes(self) -> int:
        """分片偏移量（字节）"""
        return self.fragment_offset * 8
    
    @property
    def protocol_name(self) -> str:
        """协议名称"""
        names = {
            IP_PROTO_ICMP: "ICMP",
            IP_PROTO_TCP: "TCP",
            IP_PROTO_UDP: "UDP",
        }
        return names.get(self.protocol, f"0x{self.protocol:02x}")


@dataclass
class IPPacket:
    """IPv4数据包解析结果"""
    header: IPHeader = field(default_factory=IPHeader)
    payload: bytes = b""
    raw_packet: bytes = b""
    is_truncated: bool = False
    parse_error: Optional[str] = None
    checksum_valid: Optional[bool] = None
    
    @property
    def payload_length(self) -> int:
        """payload长度（字节）"""
        return len(self.payload)
    
    @property
    def is_fragmented(self) -> bool:
        """是否是分片数据包"""
        return self.header.is_fragmented
    
    def summary(self) -> str:
        """获取数据包摘要信息"""
        h = self.header
        parts = [f"IP {h.protocol_name}"]
        parts.append(f"{h.src_ip} -> {h.dst_ip}")
        parts.append(f"id={h.identification}")
        parts.append(f"ttl={h.ttl}")
        if h.is_fragmented:
            parts.append(f"frag_off={h.fragment_offset_bytes}")
            if h.mf_flag:
                parts.append("[MF]")
            if h.df_flag:
                parts.append("[DF]")
        if self.is_truncated:
            parts.append("[TRUNCATED]")
        if self.parse_error:
            parts.append(f"[ERROR: {self.parse_error}]")
        return " ".join(parts)


def parse_ipv4(packet_data: bytes) -> IPPacket:
    """
    解析IPv4数据包
    
    逐层剥离协议头的过程:
    1. 检查数据包长度是否足够容纳IP头(最小20字节)
    2. 解析版本号和IHL(第1字节的高4位和低4位)
    3. 验证版本号是否为4
    4. 根据IHL计算实际IP头长度(IHL * 4字节)
    5. 解析TOS、总长度、标识、标志+分片偏移
    6. 解析TTL、协议号、首部校验和
    7. 解析源IP和目的IP地址
    8. 如果有IP选项，解析选项字段
    9. 验证IP首部校验和
    10. 提取payload (传输层数据)
    
    Args:
        packet_data: IP数据包 (从网络层开始的原始数据)
    
    Returns:
        IPPacket: 解析后的IP数据包对象
    """
    result = IPPacket()
    result.raw_packet = packet_data
    
    if len(packet_data) < IP_MIN_HEADER_LEN:
        result.is_truncated = True
        result.parse_error = "Packet too short for IP header"
        if len(packet_data) >= 1:
            result.header.version = (packet_data[0] >> 4) & 0x0F
            result.header.ihl = packet_data[0] & 0x0F
        return result
    
    h = result.header
    
    ver_ihl = packet_data[0]
    h.version = (ver_ihl >> 4) & 0x0F
    h.ihl = ver_ihl & 0x0F
    h.ihl_bytes = h.ihl * 4
    
    if h.version != 4:
        result.parse_error = f"Not IPv4 (version={h.version})"
        return result
    
    if h.ihl_bytes < IP_MIN_HEADER_LEN or h.ihl_bytes > IP_MAX_HEADER_LEN:
        result.parse_error = f"Invalid IHL: {h.ihl} ({h.ihl_bytes} bytes)"
        return result
    
    if len(packet_data) < h.ihl_bytes:
        result.is_truncated = True
        result.parse_error = "Packet truncated in IP header"
        h.tos = packet_data[1]
        h.total_length = struct.unpack("!H", packet_data[2:4])[0]
        return result
    
    h.tos = packet_data[1]
    h.total_length = struct.unpack("!H", packet_data[2:4])[0]
    h.identification = struct.unpack("!H", packet_data[4:6])[0]
    
    flags_frag = struct.unpack("!H", packet_data[6:8])[0]
    h.flags = (flags_frag >> 13) & 0x07
    h.fragment_offset = flags_frag & IP_FRAGMENT_MASK
    
    h.ttl = packet_data[8]
    h.protocol = packet_data[9]
    h.header_checksum = struct.unpack("!H", packet_data[10:12])[0]
    
    h.src_ip = socket.inet_ntoa(packet_data[12:16])
    h.dst_ip = socket.inet_ntoa(packet_data[16:20])
    
    if h.ihl_bytes > IP_MIN_HEADER_LEN:
        h.options = packet_data[IP_MIN_HEADER_LEN:h.ihl_bytes]
    
    if len(packet_data) >= h.ihl_bytes:
        header_data = packet_data[:h.ihl_bytes]
        csum = _calculate_checksum(header_data)
        result.checksum_valid = (csum == 0)
    
    if h.total_length > 0 and len(packet_data) < h.total_length:
        result.is_truncated = True
    
    payload_start = h.ihl_bytes
    if h.total_length > 0:
        payload_end = min(h.total_length, len(packet_data))
    else:
        payload_end = len(packet_data)
    
    if payload_start < payload_end:
        result.payload = packet_data[payload_start:payload_end]
    else:
        result.payload = b""
    
    if h.total_length > 0 and len(result.payload) < (h.total_length - h.ihl_bytes):
        result.is_truncated = True
    
    return result


def _calculate_checksum(data: bytes) -> int:
    """计算IP首部校验和"""
    if len(data) % 2 == 1:
        data += b"\x00"
    
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    
    return (~total) & 0xFFFF


def get_fragment_key(packet: IPPacket) -> tuple:
    """
    获取IP分片的重组键
    
    具有相同(src_ip, dst_ip, protocol, identification)的分片属于同一数据报
    """
    h = packet.header
    return (h.src_ip, h.dst_ip, h.protocol, h.identification)


def build_ipv4(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload: bytes = b"",
    ttl: int = 64,
    identification: int = 0,
    flags: int = 0,
    fragment_offset: int = 0,
    tos: int = 0
) -> bytes:
    """构建IPv4数据包（用于测试）
    
    Args:
        flags: 标志位 (可以是 IP_FLAG_DF, IP_FLAG_MF 等完整常量值，
                     也可以是 0-7 的 3位标志值)
        fragment_offset: 分片偏移 (以8字节为单位，0-8191)
    """
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    
    ihl = 5
    total_length = ihl * 4 + len(payload)
    
    ver_ihl = (4 << 4) | ihl
    
    if flags > 0x07:
        flags_bits = (flags >> 13) & 0x07
    else:
        flags_bits = flags & 0x07
    
    flags_frag = (flags_bits << 13) | (fragment_offset & IP_FRAGMENT_MASK)
    
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        0,
        src_bytes,
        dst_bytes
    )
    
    csum = _calculate_checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    
    return header + payload
