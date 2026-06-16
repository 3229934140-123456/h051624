"""
数据包工具函数
==============
提供数据包处理的通用工具函数
"""

import struct
import socket


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

ETHERTYPE_NAME = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
    0x8035: "RARP",
    0x88CC: "LLDP",
    0x8808: "EthernetFlowControl",
    0x8847: "MPLS",
    0x8863: "PPPoEDiscovery",
    0x8864: "PPPoESession",
}

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMPV6 = 58

IP_PROTO_NAME = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


def mac_bytes_to_str(mac_bytes):
    """将6字节MAC地址转换为字符串格式"""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def mac_str_to_bytes(mac_str):
    """将MAC地址字符串转换为6字节"""
    return bytes(int(x, 16) for x in mac_str.split(":"))


def ip_bytes_to_str(ip_bytes):
    """将4字节IPv4地址转换为字符串格式"""
    return socket.inet_ntoa(ip_bytes)


def ip_str_to_bytes(ip_str):
    """将IPv4地址字符串转换为4字节"""
    return socket.inet_aton(ip_str)


def checksum(data):
    """计算IP/TCP/UDP校验和 (RFC 1071)"""
    if len(data) % 2 == 1:
        data += b"\x00"
    
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    
    return (~total) & 0xFFFF


def verify_checksum(data, checksum_field_offset):
    """验证校验和
    
    Args:
        data: 完整数据
        checksum_field_offset: 校验和字段在数据中的偏移量(2字节字段)
    
    Returns:
        bool: 校验和是否正确
    """
    original = (data[checksum_field_offset] << 8) | data[checksum_field_offset + 1]
    data_zero = data[:checksum_field_offset] + b"\x00\x00" + data[checksum_field_offset + 2:]
    calculated = checksum(data_zero)
    return original == calculated


def tuple_to_five_tuple(src_ip, dst_ip, src_port, dst_port, protocol):
    """构建五元组 (用于唯一标识一个连接)
    
    返回规范的五元组，正向和反向视为同一连接
    """
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, src_port, dst_ip, dst_port, protocol)
    else:
        return (dst_ip, dst_port, src_ip, src_port, protocol)


def is_truncated(packet_data, expected_length):
    """检查数据包是否被截断"""
    return len(packet_data) < expected_length
