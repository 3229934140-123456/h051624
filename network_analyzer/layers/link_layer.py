"""
链路层解析 - 以太网帧
======================
解析以太网帧头，提取目的MAC、源MAC、以太类型等字段。

以太网帧格式 (Ethernet II):
+-----------------+----------------+---------+-----------------+
|  Destination MAC (6B) | Source MAC (6B) | Type (2B) |   Payload   |
+-----------------+----------------+---------+-----------------+

以太类型常见值:
- 0x0800: IPv4
- 0x86DD: IPv6
- 0x0806: ARP
- 0x8100: VLAN (802.1Q)
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

ETHERNET_HEADER_LEN = 14
VLAN_HEADER_LEN = 4

ETHERNET_MIN_PAYLOAD = 46
ETHERNET_MAX_PAYLOAD = 1500
ETHERNET_MAX_FRAME = 1518


@dataclass
class EthernetFrame:
    """以太网帧解析结果"""
    
    dst_mac: str = ""
    src_mac: str = ""
    ethertype: int = 0
    vlan_id: Optional[int] = None
    vlan_priority: Optional[int] = None
    payload: bytes = b""
    raw_frame: bytes = b""
    frame_length: int = 0
    is_truncated: bool = False
    parse_error: Optional[str] = None
    
    @property
    def ethertype_name(self) -> str:
        """获取以太类型名称"""
        names = {
            ETHERTYPE_IPV4: "IPv4",
            ETHERTYPE_IPV6: "IPv6",
            ETHERTYPE_ARP: "ARP",
            ETHERTYPE_VLAN: "VLAN",
        }
        return names.get(self.ethertype, f"0x{self.ethertype:04x}")
    
    def summary(self) -> str:
        """获取帧摘要信息"""
        parts = [f"Ethernet {self.ethertype_name}"]
        parts.append(f"{self.src_mac} -> {self.dst_mac}")
        if self.vlan_id is not None:
            parts.append(f"VLAN {self.vlan_id}")
        parts.append(f"len={self.frame_length}")
        if self.is_truncated:
            parts.append("[TRUNCATED]")
        if self.parse_error:
            parts.append(f"[ERROR: {self.parse_error}]")
        return " ".join(parts)


def _parse_mac(data: bytes, offset: int) -> str:
    """从指定偏移解析6字节MAC地址"""
    return ":".join(f"{b:02x}" for b in data[offset:offset+6])


def parse_ethernet(frame_data: bytes) -> EthernetFrame:
    """
    解析以太网帧
    
    逐层剥离协议头的过程:
    1. 检查帧长度是否足够容纳以太网头(14字节)
    2. 解析目的MAC (0-5字节)
    3. 解析源MAC (6-11字节)
    4. 解析以太类型 (12-13字节)
    5. 如果是VLAN帧(0x8100)，继续解析VLAN标签
    6. 剩余部分为 payload (网络层数据)
    
    Args:
        frame_data: 原始以太网帧数据 (bytes)
    
    Returns:
        EthernetFrame: 解析后的以太网帧对象
    """
    result = EthernetFrame()
    result.raw_frame = frame_data
    result.frame_length = len(frame_data)
    
    if len(frame_data) < ETHERNET_HEADER_LEN:
        result.is_truncated = True
        result.parse_error = "Frame too short for Ethernet header"
        if len(frame_data) >= 12:
            result.dst_mac = _parse_mac(frame_data, 0)
            result.src_mac = _parse_mac(frame_data, 6)
        return result
    
    result.dst_mac = _parse_mac(frame_data, 0)
    result.src_mac = _parse_mac(frame_data, 6)
    
    ethertype = struct.unpack("!H", frame_data[12:14])[0]
    offset = 14
    
    if ethertype == ETHERTYPE_VLAN:
        if len(frame_data) < offset + VLAN_HEADER_LEN:
            result.is_truncated = True
            result.parse_error = "Frame truncated in VLAN header"
            result.ethertype = ethertype
            return result
        
        tci = struct.unpack("!H", frame_data[offset:offset+2])[0]
        result.vlan_priority = (tci >> 13) & 0x7
        result.vlan_id = tci & 0x0FFF
        offset += 2
        
        ethertype = struct.unpack("!H", frame_data[offset:offset+2])[0]
        offset += 2
    
    result.ethertype = ethertype
    
    if len(frame_data) < offset:
        result.is_truncated = True
        result.parse_error = "Frame truncated after headers"
    else:
        result.payload = frame_data[offset:]
        if len(result.payload) < ETHERNET_MIN_PAYLOAD:
            pass
    
    return result


def build_ethernet(
    dst_mac: str,
    src_mac: str,
    ethertype: int,
    payload: bytes = b"",
    vlan_id: Optional[int] = None,
    vlan_priority: int = 0
) -> bytes:
    """构建以太网帧（用于测试）"""
    dst_bytes = bytes(int(x, 16) for x in dst_mac.split(":"))
    src_bytes = bytes(int(x, 16) for x in src_mac.split(":"))
    
    frame = dst_bytes + src_bytes
    
    if vlan_id is not None:
        tci = (vlan_priority & 0x7) << 13 | (vlan_id & 0x0FFF)
        frame += struct.pack("!HH", ETHERTYPE_VLAN, tci)
    
    frame += struct.pack("!H", ethertype)
    frame += payload
    
    return frame
