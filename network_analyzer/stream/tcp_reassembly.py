"""
TCP流重组
==========
将TCP段按序列号重组成连续的字节流，处理乱序、重传、丢包等情况。

TCP流重组原理:
1. 每个方向的数据流独立维护一个接收缓冲区
2. 初始序列号(ISN)由SYN包确定
3. 数据按序列号存放，允许乱序到达
4. 当从期望的下一个序列号开始有连续数据时，将数据交付给应用层
5. 重传的数据(序列号已确认过)被忽略
6. SYN和FIN各占用一个序列号

核心数据结构:
- 接收缓冲区: 存储已收到但尚未按序交付的数据片段
- 期望序列号: 下一个期望接收的序列号
- 乱序队列: 按序列号排序的未就绪数据片段

连接状态跟踪:
- CLOSED: 初始状态
- SYN_SENT: 已发送SYN
- SYN_RECV: 已收到SYN
- ESTABLISHED: 连接建立
- FIN_WAIT: 已发送FIN
- CLOSE_WAIT: 已收到FIN
- CLOSED: 连接关闭

五元组标识一个连接:
(src_ip, src_port, dst_ip, dst_port, protocol)
其中protocol固定为6(TCP)
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Deque
from collections import deque
import struct

from ..layers.transport_layer import (
    TCPSegment,
    TCP_FLAG_SYN,
    TCP_FLAG_FIN,
    TCP_FLAG_ACK,
    TCP_FLAG_RST,
)
from ..layers.network_layer import IPPacket


SEQ_UNSET = -1


@dataclass
class TCPDataSegment:
    """TCP数据片段 (用于重组缓冲区)"""
    seq: int
    data: bytes
    
    @property
    def end(self) -> int:
        return self.seq + len(self.data)
    
    def __len__(self) -> int:
        return len(self.data)


@dataclass
class TCPStreamHalf:
    """TCP流的一个方向的数据"""
    ip: str = ""
    port: int = 0
    isn: int = SEQ_UNSET
    next_seq: int = SEQ_UNSET
    max_seq: int = SEQ_UNSET
    
    segments: List[TCPDataSegment] = field(default_factory=list)
    
    bytes_received: int = 0
    bytes_delivered: int = 0
    segment_count: int = 0
    duplicate_bytes: int = 0
    out_of_order_count: int = 0
    
    has_syn: bool = False
    has_fin: bool = False
    fin_seq: int = SEQ_UNSET
    
    state: str = "CLOSED"
    
    def add_segment(self, seq: int, data: bytes) -> bytes:
        """
        添加一个TCP数据段，返回新的可交付数据
        
        Args:
            seq: 数据起始序列号
            data: 数据内容
        
        Returns:
            bytes: 新交付的连续数据 (从next_seq开始的连续数据)
        """
        self.segment_count += 1
        self.bytes_received += len(data)
        
        if self.next_seq == SEQ_UNSET:
            if not data:
                return b""
            self.next_seq = seq
        
        end = seq + len(data)
        
        if end <= self.next_seq:
            self.duplicate_bytes += len(data)
            return b""
        
        if seq < self.next_seq:
            trim = self.next_seq - seq
            seq = self.next_seq
            data = data[trim:]
            self.duplicate_bytes += trim
        
        if not data:
            return b""
        
        if seq == self.next_seq:
            delivered = data
            self.next_seq += len(data)
            self.bytes_delivered += len(data)
            extra = self._flush_ordered_segments()
            if extra:
                delivered += extra
            return delivered
        else:
            self.out_of_order_count += 1
            self._insert_out_of_order(seq, data)
            return b""
    
    def _insert_out_of_order(self, seq: int, data: bytes):
        """插入乱序数据段到缓冲区"""
        new_seg = TCPDataSegment(seq=seq, data=data)
        
        if not self.segments:
            self.segments.append(new_seg)
            return
        
        insert_idx = len(self.segments)
        for i, seg in enumerate(self.segments):
            if seg.seq > seq:
                insert_idx = i
                break
        
        self.segments.insert(insert_idx, new_seg)
        self._merge_segments()
    
    def _merge_segments(self):
        """合并重叠或相邻的数据段"""
        if len(self.segments) <= 1:
            return
        
        merged = [self.segments[0]]
        for seg in self.segments[1:]:
            last = merged[-1]
            
            if seg.seq <= last.end:
                if seg.end > last.end:
                    overlap = last.end - seg.seq
                    new_data = last.data + seg.data[overlap:]
                    merged[-1] = TCPDataSegment(
                        seq=last.seq,
                        data=new_data
                    )
                    self.duplicate_bytes += overlap
            elif seg.seq == last.end:
                merged[-1] = TCPDataSegment(
                    seq=last.seq,
                    data=last.data + seg.data
                )
            else:
                merged.append(seg)
        
        self.segments = merged
    
    def _flush_ordered_segments(self) -> bytes:
        """冲刷已排序的连续数据，返回新增的交付数据"""
        delivered = b""
        
        while self.segments and self.segments[0].seq == self.next_seq:
            seg = self.segments.pop(0)
            delivered += seg.data
            self.next_seq += len(seg.data)
            self.bytes_delivered += len(seg.data)
        
        return delivered
    
    def get_buffered_data(self) -> bytes:
        """获取缓冲区中所有数据(不一定连续)"""
        return b"".join(seg.data for seg in self.segments)
    
    def get_contiguous_data(self) -> bytes:
        """获取从next_seq开始的连续数据(如果有的话)"""
        if not self.segments or self.segments[0].seq != self.next_seq:
            return b""
        return self._flush_ordered_segments()
    
    def has_gap(self) -> bool:
        """检查是否存在数据缺口"""
        if not self.segments:
            return False
        return self.segments[0].seq > self.next_seq
    
    def gap_size(self) -> int:
        """获取第一个缺口的大小(字节)"""
        if not self.has_gap():
            return 0
        return self.segments[0].seq - self.next_seq


@dataclass
class TCPConnection:
    """TCP连接 (五元组标识)"""
    five_tuple: Tuple[str, int, str, int, int]
    
    client_to_server: TCPStreamHalf = field(default_factory=TCPStreamHalf)
    server_to_client: TCPStreamHalf = field(default_factory=TCPStreamHalf)
    
    state: str = "CLOSED"
    start_time: float = field(default_factory=time.time)
    last_active_time: float = field(default_factory=time.time)
    
    total_packets: int = 0
    total_bytes: int = 0
    
    client_ip: str = ""
    client_port: int = 0
    server_ip: str = ""
    server_port: int = 0
    
    def __post_init__(self):
        src_ip, src_port, dst_ip, dst_port, proto = self.five_tuple
        if (src_ip, src_port) < (dst_ip, dst_port):
            self.client_ip = src_ip
            self.client_port = src_port
            self.server_ip = dst_ip
            self.server_port = dst_port
        else:
            self.client_ip = dst_ip
            self.client_port = dst_port
            self.server_ip = src_ip
            self.server_port = src_port
        
        self.client_to_server.ip = self.client_ip
        self.client_to_server.port = self.client_port
        self.server_to_client.ip = self.server_ip
        self.server_to_client.port = self.server_port
    
    def process_segment(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        tcp: TCPSegment
    ) -> Tuple[bytes, bytes]:
        """
        处理一个TCP段，返回两个方向新交付的数据
        
        Args:
            src_ip: 源IP
            src_port: 源端口
            dst_ip: 目的IP
            dst_port: 目的端口
            tcp: TCP段解析结果
        
        Returns:
            Tuple[bytes, bytes]: (client->server新数据, server->client新数据)
        """
        self.total_packets += 1
        self.total_bytes += len(tcp.raw_segment)
        self.last_active_time = time.time()
        
        is_client_to_server = (src_ip == self.client_ip and src_port == self.client_port)
        
        if is_client_to_server:
            stream = self.client_to_server
            other_stream = self.server_to_client
        else:
            stream = self.server_to_client
            other_stream = self.client_to_server
        
        self._update_state(tcp, is_client_to_server)
        
        if not stream.has_syn and tcp.syn:
            stream.has_syn = True
            stream.isn = tcp.seq
            stream.next_seq = tcp.seq + 1
            stream.state = "SYN_RECV"
        
        if tcp.fin and not stream.has_fin:
            stream.has_fin = True
            stream.fin_seq = tcp.seq
            if stream.next_seq == SEQ_UNSET:
                stream.next_seq = tcp.seq + 1
            else:
                pass
        
        if tcp.payload:
            data_start = tcp.seq
            if tcp.syn:
                data_start += 1
            
            delivered = stream.add_segment(data_start, tcp.payload)
        else:
            delivered = b""
        
        if is_client_to_server:
            return (delivered, b"")
        else:
            return (b"", delivered)
    
    def _update_state(self, tcp: TCPSegment, is_client_to_server: bool):
        """更新连接状态"""
        if tcp.rst:
            self.state = "CLOSED"
            return
        
        if self.state == "CLOSED":
            if tcp.syn and not tcp.ack_flag:
                self.state = "SYN_SENT"
            elif tcp.syn and tcp.ack_flag:
                self.state = "SYN_RECV"
        elif self.state == "SYN_SENT":
            if tcp.syn and tcp.ack_flag:
                self.state = "SYN_RECV"
            elif tcp.ack_flag:
                self.state = "ESTABLISHED"
        elif self.state == "SYN_RECV":
            if tcp.ack_flag:
                self.state = "ESTABLISHED"
        elif self.state == "ESTABLISHED":
            if tcp.fin:
                self.state = "CLOSE_WAIT"
        elif self.state == "CLOSE_WAIT":
            if tcp.ack_flag and is_client_to_server:
                pass
            elif tcp.fin:
                pass
        
        if self.client_to_server.has_fin and self.server_to_client.has_fin:
            self.state = "CLOSED"
    
    @property
    def is_established(self) -> bool:
        return self.state == "ESTABLISHED"
    
    @property
    def is_closed(self) -> bool:
        return self.state == "CLOSED"
    
    def summary(self) -> str:
        """获取连接摘要"""
        parts = [
            f"{self.client_ip}:{self.client_port} -> {self.server_ip}:{self.server_port}",
            f"state={self.state}",
            f"packets={self.total_packets}",
            f"bytes={self.total_bytes}",
        ]
        return " ".join(parts)


class TCPStreamReassembler:
    """
    TCP流重组器
    
    管理多个TCP连接的流重组，支持乱序、重传、连接状态跟踪。
    
    使用方法:
        reassembler = TCPStreamReassembler()
        client_data, server_data = reassembler.process(ip_packet, tcp_segment)
    """
    
    def __init__(self, timeout: float = 300.0):
        """
        初始化TCP流重组器
        
        Args:
            timeout: 连接超时时间(秒)
        """
        self.timeout = timeout
        self._connections: Dict[Tuple, TCPConnection] = {}
        self._lock = threading.Lock()
        self._stats = {
            "total_segments": 0,
            "total_connections": 0,
            "established_connections": 0,
            "closed_connections": 0,
            "timed_out_connections": 0,
            "out_of_order_segments": 0,
            "duplicate_bytes": 0,
        }
    
    def process(self, ip: IPPacket, tcp: TCPSegment) -> Tuple[str, int, str, int, bytes, bytes]:
        """
        处理一个TCP段，返回连接信息和新交付的数据
        
        Args:
            ip: IP数据包
            tcp: TCP段
        
        Returns:
            Tuple: (src_ip, src_port, dst_ip, dst_port, client_data, server_data)
        """
        self._cleanup_expired()
        
        src_ip = ip.header.src_ip
        dst_ip = ip.header.dst_ip
        src_port = tcp.src_port
        dst_port = tcp.dst_port
        
        five_tuple = self._make_five_tuple(src_ip, src_port, dst_ip, dst_port)
        
        with self._lock:
            self._stats["total_segments"] += 1
            
            if five_tuple not in self._connections:
                self._connections[five_tuple] = TCPConnection(five_tuple)
                self._stats["total_connections"] += 1
            
            conn = self._connections[five_tuple]
            was_established = conn.is_established
            
            c2s_data, s2c_data = conn.process_segment(
                src_ip, src_port, dst_ip, dst_port, tcp
            )
            
            if not was_established and conn.is_established:
                self._stats["established_connections"] += 1
            
            if conn.is_closed:
                self._stats["closed_connections"] += 1
                del self._connections[five_tuple]
            
            self._stats["out_of_order_segments"] += (
                conn.client_to_server.out_of_order_count +
                conn.server_to_client.out_of_order_count
            )
            self._stats["duplicate_bytes"] += (
                conn.client_to_server.duplicate_bytes +
                conn.server_to_client.duplicate_bytes
            )
        
        return (src_ip, src_port, dst_ip, dst_port, c2s_data, s2c_data)
    
    def _make_five_tuple(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int
    ) -> Tuple:
        """构造规范的五元组 (正向和反向视为同一连接)"""
        proto = 6
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port, proto)
        else:
            return (dst_ip, dst_port, src_ip, src_port, proto)
    
    def get_connection(self, five_tuple: Tuple) -> Optional[TCPConnection]:
        """获取指定连接"""
        with self._lock:
            return self._connections.get(five_tuple)
    
    def get_all_connections(self) -> List[TCPConnection]:
        """获取所有活跃连接"""
        with self._lock:
            return list(self._connections.values())
    
    def _cleanup_expired(self):
        """清理超时的连接"""
        now = time.time()
        with self._lock:
            expired_keys = [
                key for key, conn in self._connections.items()
                if (now - conn.last_active_time) > self.timeout
            ]
            for key in expired_keys:
                del self._connections[key]
                self._stats["timed_out_connections"] += 1
    
    def get_stats(self) -> Dict:
        """获取重组统计信息"""
        stats = dict(self._stats)
        stats["active_connections"] = len(self._connections)
        return stats
    
    def reset(self):
        """重置重组器"""
        with self._lock:
            self._connections.clear()
            self._stats = {
                "total_segments": 0,
                "total_connections": 0,
                "established_connections": 0,
                "closed_connections": 0,
                "timed_out_connections": 0,
                "out_of_order_segments": 0,
                "duplicate_bytes": 0,
            }


def get_five_tuple_key(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: int = 6
) -> Tuple:
    """
    生成规范的五元组键
    
    用于唯一标识一个TCP/UDP连接，正向和反向返回相同的键。
    按字典序排序，确保(src,dst)和(dst,src)得到相同的键。
    
    Args:
        src_ip: 源IP
        src_port: 源端口
        dst_ip: 目的IP
        dst_port: 目的端口
        protocol: 协议号 (默认6=TCP)
    
    Returns:
        Tuple: 规范五元组 (ip1, port1, ip2, port2, protocol)
    """
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, src_port, dst_ip, dst_port, protocol)
    else:
        return (dst_ip, dst_port, src_ip, src_port, protocol)
