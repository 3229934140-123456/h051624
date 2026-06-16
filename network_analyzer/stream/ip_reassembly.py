"""
IP分片重组
===========
将属于同一IP数据报的多个分片重组为完整的IP数据包。

IP分片重组算法:
1. 每个分片具有相同的(src_ip, dst_ip, protocol, identification)作为重组键
2. 分片以8字节为单位，分片偏移字段表示该分片在原数据报中的位置(以8字节为单位)
3. MF(More Fragments)标志位为0表示这是最后一个分片
4. 只有第一个分片(offset=0)包含传输层头
5. 重组时需要处理:
   - 分片重叠 (需要合并去重)
   - 分片乱序 (按偏移排序)
   - 分片丢失 (超时清理)
   - 第一个分片缺失 (无法解析传输层)

重组完成条件:
- 从offset=0开始到最后一个分片的结束位置之间没有间隙
- 最后一个分片的MF标志为0
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
import struct
import socket

from ..layers.network_layer import IPPacket, parse_ipv4, IP_FLAG_MF, IP_FRAGMENT_MASK


@dataclass
class IPFragment:
    """IP分片信息"""
    offset: int
    length: int
    data: bytes
    is_last: bool
    packet: IPPacket
    
    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass
class IPReassemblyBuffer:
    """IP分片重组缓冲区
    
    保存同一数据报的所有分片，等待重组完成
    """
    key: Tuple[str, str, int, int]
    fragments: List[IPFragment] = field(default_factory=list)
    total_length: Optional[int] = None
    first_fragment: Optional[IPPacket] = None
    last_fragment_offset: Optional[int] = None
    created_time: float = field(default_factory=time.time)
    last_update_time: float = field(default_factory=time.time)
    complete: bool = False
    reassembled_data: Optional[bytes] = None
    
    def add_fragment(self, packet: IPPacket) -> bool:
        """
        添加一个分片到重组缓冲区
        
        Args:
            packet: IP分片数据包
        
        Returns:
            bool: 如果添加后数据报重组完成返回True
        """
        h = packet.header
        offset = h.fragment_offset_bytes
        length = len(packet.payload)
        is_last = not h.mf_flag
        
        frag = IPFragment(
            offset=offset,
            length=length,
            data=packet.payload,
            is_last=is_last,
            packet=packet
        )
        
        if offset == 0:
            self.first_fragment = packet
        
        if is_last:
            self.last_fragment_offset = offset
            self.total_length = offset + length
        
        self.fragments.append(frag)
        self.last_update_time = time.time()
        
        self._merge_fragments()
        
        if self._is_complete():
            self.complete = True
            self.reassembled_data = self._assemble_data()
            return True
        
        return False
    
    def _merge_fragments(self):
        """合并重叠或相邻的分片"""
        if not self.fragments:
            return
        
        self.fragments.sort(key=lambda f: f.offset)
        
        merged = [self.fragments[0]]
        for frag in self.fragments[1:]:
            last = merged[-1]
            
            if frag.offset <= last.end:
                if frag.end > last.end:
                    overlap = last.end - frag.offset
                    new_data = last.data + frag.data[overlap:]
                    merged[-1] = IPFragment(
                        offset=last.offset,
                        length=len(new_data),
                        data=new_data,
                        is_last=frag.is_last,
                        packet=frag.packet
                    )
                elif frag.end == last.end and frag.is_last:
                    merged[-1].is_last = True
            else:
                merged.append(frag)
        
        self.fragments = merged
    
    def _is_complete(self) -> bool:
        """检查数据报是否重组完成"""
        if not self.fragments:
            return False
        
        if self.fragments[0].offset != 0:
            return False
        
        last_frag = self.fragments[-1]
        if not last_frag.is_last:
            return False
        
        current_end = 0
        for frag in self.fragments:
            if frag.offset > current_end:
                return False
            current_end = max(current_end, frag.end)
        
        return True
    
    def _assemble_data(self) -> bytes:
        """组装重组后的数据"""
        if not self.complete and not self._is_complete():
            return b""
        
        self.fragments.sort(key=lambda f: f.offset)
        
        result = b""
        for frag in self.fragments:
            result += frag.data
        
        return result
    
    def get_reassembled_packet(self) -> Optional[IPPacket]:
        """获取重组后的完整IP数据包"""
        if not self.complete or not self.first_fragment or self.reassembled_data is None:
            return None
        
        orig_header = self.first_fragment.header
        
        new_total_length = orig_header.ihl_bytes + len(self.reassembled_data)
        
        new_packet_data = bytearray(self.first_fragment.raw_packet[:orig_header.ihl_bytes])
        
        struct.pack_into("!H", new_packet_data, 2, new_total_length)
        struct.pack_into("!H", new_packet_data, 6, 0)
        struct.pack_into("!H", new_packet_data, 10, 0)
        
        header_data = bytes(new_packet_data[:orig_header.ihl_bytes])
        csum = self._calc_header_checksum(header_data)
        struct.pack_into("!H", new_packet_data, 10, csum)
        
        new_packet_data.extend(self.reassembled_data)
        
        return parse_ipv4(bytes(new_packet_data))
    
    def _calc_header_checksum(self, header: bytes) -> int:
        """计算IP首部校验和"""
        if len(header) % 2 == 1:
            header += b"\x00"
        
        total = 0
        for i in range(0, len(header), 2):
            word = (header[i] << 8) + header[i + 1]
            total += word
        
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        
        return (~total) & 0xFFFF
    
    def is_expired(self, timeout: float = 30.0) -> bool:
        """检查重组缓冲区是否超时"""
        return (time.time() - self.last_update_time) > timeout


class IPReassembler:
    """
    IP分片重组器
    
    管理多个IP数据报的分片重组，处理超时清理。
    
    使用方法:
        reassembler = IPReassembler()
        result = reassembler.process(ip_packet)
        if result is not None:
            # 处理重组后的完整数据包
    """
    
    def __init__(self, timeout: float = 30.0):
        """
        初始化IP分片重组器
        
        Args:
            timeout: 分片重组超时时间(秒)
        """
        self.timeout = timeout
        self._buffers: Dict[Tuple[str, str, int, int], IPReassemblyBuffer] = {}
        self._lock = threading.Lock()
        self._stats = {
            "total_fragments": 0,
            "reassembled_datagrams": 0,
            "timed_out_datagrams": 0,
            "overlapping_fragments": 0,
        }
    
    def process(self, packet: IPPacket) -> Optional[IPPacket]:
        """
        处理一个IP数据包
        
        如果是分片，加入重组缓冲区。如果重组完成，返回重组后的完整数据包。
        如果不是分片，直接返回原数据包。
        
        Args:
            packet: IP数据包
        
        Returns:
            Optional[IPPacket]: 完整的IP数据包(如果重组完成或不是分片)，
                               None表示分片已加入缓冲区但尚未完成
        """
        if not packet.is_fragmented:
            return packet
        
        self._cleanup_expired()
        
        self._stats["total_fragments"] += 1
        key = self._get_fragment_key(packet)
        
        with self._lock:
            if key not in self._buffers:
                self._buffers[key] = IPReassemblyBuffer(key=key)
            
            buf = self._buffers[key]
            is_complete = buf.add_fragment(packet)
            
            if is_complete:
                self._stats["reassembled_datagrams"] += 1
                reassembled = buf.get_reassembled_packet()
                del self._buffers[key]
                return reassembled
        
        return None
    
    def _get_fragment_key(self, packet: IPPacket) -> Tuple[str, str, int, int]:
        """获取分片重组键"""
        h = packet.header
        return (h.src_ip, h.dst_ip, h.protocol, h.identification)
    
    def _cleanup_expired(self):
        """清理超时的重组缓冲区"""
        with self._lock:
            expired_keys = [
                key for key, buf in self._buffers.items()
                if buf.is_expired(self.timeout)
            ]
            for key in expired_keys:
                del self._buffers[key]
                self._stats["timed_out_datagrams"] += 1
    
    def get_stats(self) -> Dict:
        """获取重组统计信息"""
        stats = dict(self._stats)
        stats["pending_buffers"] = len(self._buffers)
        return stats
    
    def reset(self):
        """重置重组器"""
        with self._lock:
            self._buffers.clear()
            self._stats = {
                "total_fragments": 0,
                "reassembled_datagrams": 0,
                "timed_out_datagrams": 0,
                "overlapping_fragments": 0,
            }


def fragment_ip_packet(
    packet_data: bytes,
    mtu: int = 1500
) -> List[bytes]:
    """
    将一个大的IP数据包分片 (用于测试)
    
    Args:
        packet_data: 原始IP数据包
        mtu: 最大传输单元(字节)
    
    Returns:
        List[bytes]: 分片后的IP数据包列表
    """
    parsed = parse_ipv4(packet_data)
    if not parsed:
        return [packet_data]
    
    h = parsed.header
    header_len = h.ihl_bytes
    
    max_payload = mtu - header_len
    max_payload = (max_payload // 8) * 8
    
    payload = parsed.payload
    
    if len(payload) <= max_payload:
        return [packet_data]
    
    fragments = []
    offset = 0
    frag_offset_blocks = 0
    
    while offset < len(payload):
        chunk_size = min(max_payload, len(payload) - offset)
        is_last = offset + chunk_size >= len(payload)
        
        if not is_last:
            chunk_size = (chunk_size // 8) * 8
        
        flags = 0 if is_last else IP_FLAG_MF
        
        total_len = header_len + chunk_size
        flags_frag = flags | frag_offset_blocks
        
        src_bytes = socket.inet_aton(h.src_ip)
        dst_bytes = socket.inet_aton(h.dst_ip)
        
        ver_ihl = (h.version << 4) | (header_len // 4)
        
        header = struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl,
            h.tos,
            total_len,
            h.identification,
            flags_frag,
            h.ttl,
            h.protocol,
            0,
            src_bytes,
            dst_bytes
        )
        
        csum = _calc_checksum(header)
        header = header[:10] + struct.pack("!H", csum) + header[12:]
        
        frag_packet = header + payload[offset:offset + chunk_size]
        fragments.append(frag_packet)
        
        offset += chunk_size
        frag_offset_blocks += chunk_size // 8
    
    return fragments


def _calc_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    
    return (~total) & 0xFFFF
