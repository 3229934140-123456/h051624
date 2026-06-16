"""
传输层解析 - TCP/UDP
=====================
解析TCP段和UDP数据包，提取端口、序号、标志位等字段。

TCP头格式:
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

UDP头格式:
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|
|          data octets ...
+---------------- ...
"""

import struct
import socket
from dataclasses import dataclass, field
from typing import Optional, List, Set


TCP_MIN_HEADER_LEN = 20
TCP_MAX_HEADER_LEN = 60
UDP_HEADER_LEN = 8

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20
TCP_FLAG_ECE = 0x40
TCP_FLAG_CWR = 0x80


@dataclass
class TCPSegment:
    """TCP段解析结果"""
    
    src_port: int = 0
    dst_port: int = 0
    seq: int = 0
    ack: int = 0
    data_offset: int = 5
    data_offset_bytes: int = 20
    reserved: int = 0
    flags: int = 0
    window_size: int = 0
    checksum: int = 0
    urgent_pointer: int = 0
    options: bytes = b""
    payload: bytes = b""
    raw_segment: bytes = b""
    is_truncated: bool = False
    parse_error: Optional[str] = None
    checksum_valid: Optional[bool] = None
    
    @property
    def fin(self) -> bool:
        return bool(self.flags & TCP_FLAG_FIN)
    
    @property
    def syn(self) -> bool:
        return bool(self.flags & TCP_FLAG_SYN)
    
    @property
    def rst(self) -> bool:
        return bool(self.flags & TCP_FLAG_RST)
    
    @property
    def psh(self) -> bool:
        return bool(self.flags & TCP_FLAG_PSH)
    
    @property
    def ack_flag(self) -> bool:
        return bool(self.flags & TCP_FLAG_ACK)
    
    @property
    def urg(self) -> bool:
        return bool(self.flags & TCP_FLAG_URG)
    
    @property
    def flags_str(self) -> str:
        """获取标志位字符串表示"""
        flag_names = []
        if self.cwr:
            flag_names.append("CWR")
        if self.ece:
            flag_names.append("ECE")
        if self.urg:
            flag_names.append("URG")
        if self.ack_flag:
            flag_names.append("ACK")
        if self.psh:
            flag_names.append("PSH")
        if self.rst:
            flag_names.append("RST")
        if self.syn:
            flag_names.append("SYN")
        if self.fin:
            flag_names.append("FIN")
        return ",".join(flag_names) if flag_names else "none"
    
    @property
    def cwr(self) -> bool:
        return bool(self.flags & TCP_FLAG_CWR)
    
    @property
    def ece(self) -> bool:
        return bool(self.flags & TCP_FLAG_ECE)
    
    @property
    def payload_length(self) -> int:
        return len(self.payload)
    
    @property
    def seq_end(self) -> int:
        """
        计算数据的结束序号(不包含)
        
        TCP序号计算:
        - SYN和FIN各占一个序号
        - 数据按字节计数
        """
        end = self.seq + len(self.payload)
        if self.syn:
            end += 1
        if self.fin:
            end += 1
        return end
    
    @property
    def length(self) -> int:
        """TCP段数据长度(含SYN/FIN的序号占用)"""
        length = len(self.payload)
        if self.syn:
            length += 1
        if self.fin:
            length += 1
        return length
    
    def summary(self) -> str:
        """获取TCP段摘要信息"""
        parts = ["TCP"]
        parts.append(f"{self.src_port} -> {self.dst_port}")
        parts.append(f"seq={self.seq}")
        if self.ack_flag:
            parts.append(f"ack={self.ack}")
        parts.append(f"flags=[{self.flags_str}]")
        parts.append(f"win={self.window_size}")
        parts.append(f"len={self.payload_length}")
        if self.is_truncated:
            parts.append("[TRUNCATED]")
        if self.parse_error:
            parts.append(f"[ERROR: {self.parse_error}]")
        return " ".join(parts)


@dataclass
class UDPPacket:
    """UDP数据包解析结果"""
    
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    checksum: int = 0
    payload: bytes = b""
    raw_packet: bytes = b""
    is_truncated: bool = False
    parse_error: Optional[str] = None
    checksum_valid: Optional[bool] = None
    
    @property
    def payload_length(self) -> int:
        return len(self.payload)
    
    def summary(self) -> str:
        """获取UDP数据包摘要信息"""
        parts = ["UDP"]
        parts.append(f"{self.src_port} -> {self.dst_port}")
        parts.append(f"len={self.length}")
        if self.is_truncated:
            parts.append("[TRUNCATED]")
        if self.parse_error:
            parts.append(f"[ERROR: {self.parse_error}]")
        return " ".join(parts)


def parse_tcp(segment_data: bytes, src_ip: str = "", dst_ip: str = "") -> TCPSegment:
    """
    解析TCP段
    
    逐层剥离协议头的过程:
    1. 检查数据长度是否足够容纳TCP头(最小20字节)
    2. 解析源端口、目的端口 (0-3字节)
    3. 解析序列号 (4-7字节)
    4. 解析确认号 (8-11字节)
    5. 解析数据偏移和保留位 (第12字节高4位和低3位)
    6. 解析标志位 (第13字节)
    7. 解析窗口大小 (14-15字节)
    8. 解析校验和、紧急指针 (16-19字节)
    9. 根据数据偏移解析TCP选项 (20字节后的数据偏移部分)
    10. 提取payload (应用层数据)
    11. 验证TCP校验和(需要伪首部)
    
    Args:
        segment_data: TCP段数据 (从传输层开始的原始数据)
        src_ip: 源IP地址 (用于校验和计算)
        dst_ip: 目的IP地址 (用于校验和计算)
    
    Returns:
        TCPSegment: 解析后的TCP段对象
    """
    result = TCPSegment()
    result.raw_segment = segment_data
    
    if len(segment_data) < TCP_MIN_HEADER_LEN:
        result.is_truncated = True
        result.parse_error = "Segment too short for TCP header"
        if len(segment_data) >= 4:
            result.src_port = struct.unpack("!H", segment_data[0:2])[0]
            result.dst_port = struct.unpack("!H", segment_data[2:4])[0]
        return result
    
    result.src_port = struct.unpack("!H", segment_data[0:2])[0]
    result.dst_port = struct.unpack("!H", segment_data[2:4])[0]
    result.seq = struct.unpack("!I", segment_data[4:8])[0]
    result.ack = struct.unpack("!I", segment_data[8:12])[0]
    
    data_off_res = segment_data[12]
    result.data_offset = (data_off_res >> 4) & 0x0F
    result.data_offset_bytes = result.data_offset * 4
    result.reserved = data_off_res & 0x0F
    
    result.flags = segment_data[13]
    result.window_size = struct.unpack("!H", segment_data[14:16])[0]
    result.checksum = struct.unpack("!H", segment_data[16:18])[0]
    result.urgent_pointer = struct.unpack("!H", segment_data[18:20])[0]
    
    if result.data_offset_bytes < TCP_MIN_HEADER_LEN or result.data_offset_bytes > TCP_MAX_HEADER_LEN:
        result.parse_error = f"Invalid data offset: {result.data_offset} ({result.data_offset_bytes} bytes)"
        return result
    
    if len(segment_data) < result.data_offset_bytes:
        result.is_truncated = True
        result.parse_error = "Segment truncated in TCP header"
        return result
    
    if result.data_offset_bytes > TCP_MIN_HEADER_LEN:
        result.options = segment_data[TCP_MIN_HEADER_LEN:result.data_offset_bytes]
    
    payload_start = result.data_offset_bytes
    result.payload = segment_data[payload_start:]
    
    if src_ip and dst_ip:
        try:
            pseudo = _build_tcp_pseudo_header(
                src_ip, dst_ip, len(segment_data)
            )
            csum_data = pseudo + segment_data
            csum = _calculate_checksum(csum_data)
            result.checksum_valid = (csum == 0)
        except Exception:
            result.checksum_valid = None
    
    return result


def parse_udp(packet_data: bytes, src_ip: str = "", dst_ip: str = "") -> UDPPacket:
    """
    解析UDP数据包
    
    逐层剥离协议头的过程:
    1. 检查数据长度是否足够容纳UDP头(8字节)
    2. 解析源端口、目的端口 (0-3字节)
    3. 解析长度、校验和 (4-7字节)
    4. 提取payload (应用层数据)
    5. 验证UDP校验和(需要伪首部)
    
    Args:
        packet_data: UDP数据包数据 (从传输层开始的原始数据)
        src_ip: 源IP地址 (用于校验和计算)
        dst_ip: 目的IP地址 (用于校验和计算)
    
    Returns:
        UDPPacket: 解析后的UDP数据包对象
    """
    result = UDPPacket()
    result.raw_packet = packet_data
    
    if len(packet_data) < UDP_HEADER_LEN:
        result.is_truncated = True
        result.parse_error = "Packet too short for UDP header"
        if len(packet_data) >= 4:
            result.src_port = struct.unpack("!H", packet_data[0:2])[0]
            result.dst_port = struct.unpack("!H", packet_data[2:4])[0]
        return result
    
    result.src_port = struct.unpack("!H", packet_data[0:2])[0]
    result.dst_port = struct.unpack("!H", packet_data[2:4])[0]
    result.length = struct.unpack("!H", packet_data[4:6])[0]
    result.checksum = struct.unpack("!H", packet_data[6:8])[0]
    
    if result.length > 0 and len(packet_data) < result.length:
        result.is_truncated = True
    
    payload_len = result.length - UDP_HEADER_LEN if result.length > 0 else len(packet_data) - UDP_HEADER_LEN
    if payload_len > 0:
        result.payload = packet_data[UDP_HEADER_LEN:UDP_HEADER_LEN + payload_len]
    else:
        result.payload = b""
    
    if src_ip and dst_ip and result.checksum != 0:
        try:
            pseudo = _build_udp_pseudo_header(
                src_ip, dst_ip, len(packet_data)
            )
            csum_data = pseudo + packet_data
            csum = _calculate_checksum(csum_data)
            result.checksum_valid = (csum == 0)
        except Exception:
            result.checksum_valid = None
    
    return result


def _build_tcp_pseudo_header(src_ip: str, dst_ip: str, tcp_length: int) -> bytes:
    """构建TCP伪首部 (用于校验和计算)"""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    return struct.pack("!4s4sBBH", src, dst, 0, 6, tcp_length)


def _build_udp_pseudo_header(src_ip: str, dst_ip: str, udp_length: int) -> bytes:
    """构建UDP伪首部 (用于校验和计算)"""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    return struct.pack("!4s4sBBH", src, dst, 0, 17, udp_length)


def _calculate_checksum(data: bytes) -> int:
    """计算校验和 (RFC 1071)"""
    if len(data) % 2 == 1:
        data += b"\x00"
    
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    
    return (~total) & 0xFFFF


def build_tcp(
    src_port: int,
    dst_port: int,
    seq: int = 0,
    ack: int = 0,
    flags: int = 0,
    window_size: int = 65535,
    payload: bytes = b"",
    src_ip: str = "",
    dst_ip: str = ""
) -> bytes:
    """构建TCP段（用于测试）"""
    data_offset = 5
    data_off_res = (data_offset << 4) | 0
    
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_off_res,
        flags,
        window_size,
        0,
        0
    )
    
    segment = header + payload
    
    if src_ip and dst_ip:
        pseudo = _build_tcp_pseudo_header(src_ip, dst_ip, len(segment))
        csum = _calculate_checksum(pseudo + segment)
        segment = segment[:16] + struct.pack("!H", csum) + segment[18:]
    
    return segment


def build_udp(
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
    src_ip: str = "",
    dst_ip: str = ""
) -> bytes:
    """构建UDP数据包（用于测试）"""
    length = UDP_HEADER_LEN + len(payload)
    
    packet = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        length,
        0
    ) + payload
    
    if src_ip and dst_ip:
        pseudo = _build_udp_pseudo_header(src_ip, dst_ip, length)
        csum = _calculate_checksum(pseudo + packet)
        packet = packet[:6] + struct.pack("!H", csum) + packet[8:]
    
    return packet
