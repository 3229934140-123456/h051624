"""
统计分析
=========
提供多维度的数据包统计分析功能。

统计维度:
1. 全局统计
   - 总包数、总字节数
   - 各协议包数、字节数
   - 平均包大小
   - 包速率、字节速率

2. 按协议聚合
   - 按网络层协议 (IPv4, IPv6, ARP等)
   - 按传输层协议 (TCP, UDP, ICMP等)
   - 按应用层协议 (HTTP, HTTPS, DNS等)
   - 每个协议的包数、字节数、占比

3. 按连接聚合 (五元组)
   - 每个连接的包数、字节数
   - 每个方向的包数、字节数
   - 连接持续时间
   - 连接状态

4. 按主机聚合 (IP地址)
   - 每个IP的发包数、收包数
   - 每个IP的发字节数、收字节数
   - 每个IP的连接数

5. 按端口聚合
   - 每个端口的包数、字节数
   - TCP/UDP端口分别统计

6. 时间序列统计
   - 按时间窗口统计包数、字节数
   - 用于流量趋势分析
"""

import time
import json
import csv
import io
import threading
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Optional, Any
from collections import defaultdict


@dataclass
class GlobalStats:
    """全局统计信息"""
    total_packets: int = 0
    total_bytes: int = 0
    truncated_packets: int = 0
    error_packets: int = 0
    
    start_time: float = field(default_factory=time.time)
    last_packet_time: float = 0
    
    min_packet_size: int = 0
    max_packet_size: int = 0
    total_payload_bytes: int = 0
    
    @property
    def duration(self) -> float:
        """统计持续时间(秒)"""
        if self.last_packet_time == 0:
            return 0
        return self.last_packet_time - self.start_time
    
    @property
    def avg_packet_size(self) -> float:
        """平均包大小"""
        if self.total_packets == 0:
            return 0
        return self.total_bytes / self.total_packets
    
    @property
    def packets_per_second(self) -> float:
        """每秒包数"""
        duration = self.duration
        if duration <= 0:
            return 0
        return self.total_packets / duration
    
    @property
    def bytes_per_second(self) -> float:
        """每秒字节数 (bps)"""
        duration = self.duration
        if duration <= 0:
            return 0
        return self.total_bytes / duration
    
    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.truncated_packets = 0
        self.error_packets = 0
        self.start_time = time.time()
        self.last_packet_time = 0
        self.min_packet_size = 0
        self.max_packet_size = 0
        self.total_payload_bytes = 0


@dataclass
class ProtocolStats:
    """协议统计信息"""
    packet_count: int = 0
    byte_count: int = 0
    
    def add_packet(self, size: int):
        self.packet_count += 1
        self.byte_count += size
    
    def reset(self):
        self.packet_count = 0
        self.byte_count = 0


@dataclass
class ConnectionStats:
    """连接统计信息"""
    five_tuple: Tuple[str, int, str, int, int]
    packet_count: int = 0
    byte_count: int = 0
    client_packets: int = 0
    server_packets: int = 0
    client_bytes: int = 0
    server_bytes: int = 0
    start_time: float = 0
    last_time: float = 0
    state: str = "UNKNOWN"
    app_protocol: str = "unknown"
    
    @property
    def duration(self) -> float:
        """连接持续时间"""
        if self.start_time == 0:
            return 0
        return self.last_time - self.start_time
    
    def reset(self):
        self.packet_count = 0
        self.byte_count = 0
        self.client_packets = 0
        self.server_packets = 0
        self.client_bytes = 0
        self.server_bytes = 0
        self.start_time = 0
        self.last_time = 0
        self.state = "UNKNOWN"


@dataclass
class HostStats:
    """主机统计信息"""
    ip: str = ""
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    connections: int = 0
    
    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_received
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received
    
    def reset(self):
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connections = 0


@dataclass
class TimeWindowStats:
    """时间窗口统计"""
    window_seconds: int = 1
    packet_counts: List[int] = field(default_factory=list)
    byte_counts: List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    tcp_packets: List[int] = field(default_factory=list)
    tcp_bytes: List[int] = field(default_factory=list)
    udp_packets: List[int] = field(default_factory=list)
    udp_bytes: List[int] = field(default_factory=list)
    app_protocol_packets: List[Dict[str, int]] = field(default_factory=list)
    app_protocol_bytes: List[Dict[str, int]] = field(default_factory=list)
    max_windows: int = 1000
    
    def add_packet(
        self,
        size: int,
        timestamp: float,
        is_tcp: bool = False,
        is_udp: bool = False,
        app_protocol: Optional[str] = None,
    ):
        """添加一个包到当前时间窗口"""
        if not self.timestamps:
            self._add_new_window(size, timestamp, is_tcp, is_udp, app_protocol)
            return
        
        window_start = int(timestamp / self.window_seconds) * self.window_seconds
        last_window_start = int(self.timestamps[-1] / self.window_seconds) * self.window_seconds
        
        if window_start == last_window_start:
            self.packet_counts[-1] += 1
            self.byte_counts[-1] += size
            if is_tcp:
                self.tcp_packets[-1] += 1
                self.tcp_bytes[-1] += size
            if is_udp:
                self.udp_packets[-1] += 1
                self.udp_bytes[-1] += size
            if app_protocol and app_protocol != "unknown":
                self.app_protocol_packets[-1][app_protocol] = self.app_protocol_packets[-1].get(app_protocol, 0) + 1
                self.app_protocol_bytes[-1][app_protocol] = self.app_protocol_bytes[-1].get(app_protocol, 0) + size
        else:
            self._add_new_window(size, timestamp, is_tcp, is_udp, app_protocol)
    
    def _add_new_window(
        self,
        size: int,
        timestamp: float,
        is_tcp: bool = False,
        is_udp: bool = False,
        app_protocol: Optional[str] = None,
    ):
        window_start = int(timestamp / self.window_seconds) * self.window_seconds
        self.packet_counts.append(1)
        self.byte_counts.append(size)
        self.timestamps.append(window_start)
        self.tcp_packets.append(1 if is_tcp else 0)
        self.tcp_bytes.append(size if is_tcp else 0)
        self.udp_packets.append(1 if is_udp else 0)
        self.udp_bytes.append(size if is_udp else 0)
        
        app_pkts = {}
        app_bytes = {}
        if app_protocol and app_protocol != "unknown":
            app_pkts[app_protocol] = 1
            app_bytes[app_protocol] = size
        self.app_protocol_packets.append(app_pkts)
        self.app_protocol_bytes.append(app_bytes)
        
        if len(self.packet_counts) > self.max_windows:
            self.packet_counts.pop(0)
            self.byte_counts.pop(0)
            self.timestamps.pop(0)
            self.tcp_packets.pop(0)
            self.tcp_bytes.pop(0)
            self.udp_packets.pop(0)
            self.udp_bytes.pop(0)
            self.app_protocol_packets.pop(0)
            self.app_protocol_bytes.pop(0)
    
    def reset(self):
        self.packet_counts.clear()
        self.byte_counts.clear()
        self.timestamps.clear()
        self.tcp_packets.clear()
        self.tcp_bytes.clear()
        self.udp_packets.clear()
        self.udp_bytes.clear()
        self.app_protocol_packets.clear()
        self.app_protocol_bytes.clear()


class StatisticsCollector:
    """
    统计数据收集器
    
    提供多维度的数据包统计分析功能。
    
    使用方法:
        stats = StatisticsCollector()
        stats.record_packet(ctx, timestamp)
        
        # 获取统计结果
        global_stats = stats.get_global_stats()
        protocol_stats = stats.get_protocol_stats()
        top_connections = stats.get_top_connections(10)
    """
    
    def __init__(self, time_window_seconds: int = 1):
        self._lock = threading.Lock()
        self._global = GlobalStats()
        
        self._ethertype_stats: Dict[int, ProtocolStats] = defaultdict(ProtocolStats)
        self._ip_proto_stats: Dict[int, ProtocolStats] = defaultdict(ProtocolStats)
        self._app_proto_stats: Dict[str, ProtocolStats] = defaultdict(ProtocolStats)
        
        self._connection_stats: Dict[Tuple, ConnectionStats] = {}
        
        self._host_stats: Dict[str, HostStats] = defaultdict(HostStats)
        
        self._tcp_port_stats: Dict[int, ProtocolStats] = defaultdict(ProtocolStats)
        self._udp_port_stats: Dict[int, ProtocolStats] = defaultdict(ProtocolStats)
        
        self._time_window = TimeWindowStats(window_seconds=time_window_seconds)
    
    def record_packet(self, ctx: Any, timestamp: Optional[float] = None):
        """
        记录一个数据包到统计中
        
        Args:
            ctx: 包含各层解析结果的上下文对象
            timestamp: 时间戳(秒)，默认为当前时间
        """
        if timestamp is None:
            timestamp = time.time()
        
        with self._lock:
            self._record_global(ctx, timestamp)
            self._record_protocols(ctx)
            self._record_connection(ctx, timestamp)
            self._record_hosts(ctx)
            self._record_ports(ctx)
            self._record_time_window(ctx, timestamp)
    
    def _record_global(self, ctx: Any, timestamp: float):
        """记录全局统计"""
        self._global.total_packets += 1
        
        packet_size = 0
        if ctx.ethernet:
            packet_size = len(ctx.ethernet.raw_frame)
        elif ctx.ip:
            packet_size = ctx.ip.header.total_length
        elif ctx.tcp:
            packet_size = len(ctx.tcp.raw_segment)
        elif ctx.udp:
            packet_size = ctx.udp.length
        
        self._global.total_bytes += packet_size
        self._global.last_packet_time = timestamp
        
        if packet_size > 0:
            if self._global.min_packet_size == 0 or packet_size < self._global.min_packet_size:
                self._global.min_packet_size = packet_size
            if packet_size > self._global.max_packet_size:
                self._global.max_packet_size = packet_size
        
        if ctx.ip and ctx.ip.payload:
            self._global.total_payload_bytes += len(ctx.ip.payload)
        
        if ctx.ethernet and ctx.ethernet.is_truncated:
            self._global.truncated_packets += 1
        if ctx.ip and ctx.ip.is_truncated:
            self._global.truncated_packets += 1
        
        if ctx.ethernet and ctx.ethernet.parse_error:
            self._global.error_packets += 1
        elif ctx.ip and ctx.ip.parse_error:
            self._global.error_packets += 1
    
    def _record_protocols(self, ctx: Any):
        """记录协议统计"""
        if ctx.ethernet:
            size = len(ctx.ethernet.raw_frame)
            self._ethertype_stats[ctx.ethernet.ethertype].add_packet(size)
        
        if ctx.ip:
            size = ctx.ip.header.total_length
            self._ip_proto_stats[ctx.ip.header.protocol].add_packet(size)
        
        if ctx.app_protocol and ctx.app_protocol != "unknown":
            size = 0
            if ctx.tcp:
                size = len(ctx.tcp.raw_segment)
            elif ctx.udp:
                size = ctx.udp.length
            if size > 0:
                self._app_proto_stats[ctx.app_protocol].add_packet(size)
    
    def _record_connection(self, ctx: Any, timestamp: float):
        """记录连接统计"""
        if not ctx.ip:
            return
        
        src_ip = ctx.ip.header.src_ip
        dst_ip = ctx.ip.header.dst_ip
        
        src_port = 0
        dst_port = 0
        proto = ctx.ip.header.protocol
        
        if ctx.tcp:
            src_port = ctx.tcp.src_port
            dst_port = ctx.tcp.dst_port
        elif ctx.udp:
            src_port = ctx.udp.src_port
            dst_port = ctx.udp.dst_port
        else:
            return
        
        five_tuple = self._make_five_tuple(src_ip, src_port, dst_ip, dst_port, proto)
        
        is_new_connection = five_tuple not in self._connection_stats
        if is_new_connection:
            self._connection_stats[five_tuple] = ConnectionStats(
                five_tuple=five_tuple,
                start_time=timestamp
            )
        
        conn = self._connection_stats[five_tuple]
        conn.last_time = timestamp
        
        is_client = self._is_client_side(src_ip, src_port, dst_ip, dst_port, five_tuple)
        packet_size = ctx.ip.header.total_length
        
        conn.packet_count += 1
        conn.byte_count += packet_size
        
        if is_client:
            conn.client_packets += 1
            conn.client_bytes += packet_size
        else:
            conn.server_packets += 1
            conn.server_bytes += packet_size
        
        if ctx.app_protocol:
            conn.app_protocol = ctx.app_protocol
        
        if is_new_connection:
            self._host_stats[src_ip].connections += 1
            self._host_stats[dst_ip].connections += 1
    
    def _record_hosts(self, ctx: Any):
        """记录主机统计"""
        if not ctx.ip:
            return
        
        src_ip = ctx.ip.header.src_ip
        dst_ip = ctx.ip.header.dst_ip
        size = ctx.ip.header.total_length
        
        src_host = self._host_stats[src_ip]
        src_host.ip = src_ip
        src_host.packets_sent += 1
        src_host.bytes_sent += size
        
        dst_host = self._host_stats[dst_ip]
        dst_host.ip = dst_ip
        dst_host.packets_received += 1
        dst_host.bytes_received += size
    
    def _record_ports(self, ctx: Any):
        """记录端口统计"""
        if ctx.tcp:
            size = len(ctx.tcp.raw_segment)
            self._tcp_port_stats[ctx.tcp.src_port].add_packet(size)
            self._tcp_port_stats[ctx.tcp.dst_port].add_packet(size)
        elif ctx.udp:
            size = ctx.udp.length
            self._udp_port_stats[ctx.udp.src_port].add_packet(size)
            self._udp_port_stats[ctx.udp.dst_port].add_packet(size)
    
    def _record_time_window(self, ctx: Any, timestamp: float):
        """记录时间窗口统计"""
        size = 0
        if ctx.ip:
            size = ctx.ip.header.total_length
        elif ctx.ethernet:
            size = len(ctx.ethernet.raw_frame)
        
        if size > 0:
            is_tcp = ctx.tcp is not None
            is_udp = ctx.udp is not None
            app_proto = ctx.app_protocol if hasattr(ctx, "app_protocol") else None
            self._time_window.add_packet(size, timestamp, is_tcp=is_tcp, is_udp=is_udp, app_protocol=app_proto)
    
    def _make_five_tuple(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: int
    ) -> Tuple:
        """构造规范五元组"""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port, proto)
        else:
            return (dst_ip, dst_port, src_ip, src_port, proto)
    
    def _is_client_side(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        five_tuple: Tuple
    ) -> bool:
        """判断是否是客户端方向"""
        client_ip, client_port = five_tuple[0], five_tuple[1]
        return (src_ip == client_ip and src_port == client_port)
    
    def get_global_stats(self) -> GlobalStats:
        """获取全局统计"""
        with self._lock:
            return GlobalStats(**self._global.__dict__)
    
    def get_ethertype_stats(self) -> Dict[int, ProtocolStats]:
        """获取以太类型统计"""
        with self._lock:
            return dict(self._ethertype_stats)
    
    def get_ip_proto_stats(self) -> Dict[int, ProtocolStats]:
        """获取IP协议统计"""
        with self._lock:
            return dict(self._ip_proto_stats)
    
    def get_app_proto_stats(self) -> Dict[str, ProtocolStats]:
        """获取应用层协议统计"""
        with self._lock:
            return dict(self._app_proto_stats)
    
    def get_connection_stats(self) -> Dict[Tuple, ConnectionStats]:
        """获取所有连接统计"""
        with self._lock:
            return dict(self._connection_stats)
    
    def get_top_connections(self, n: int = 10, sort_by: str = "byte_count") -> List[ConnectionStats]:
        """
        获取Top N连接
        
        Args:
            n: 返回数量
            sort_by: 排序字段 (byte_count, packet_count, duration)
        
        Returns:
            List[ConnectionStats]: 排序后的连接统计列表
        """
        with self._lock:
            connections = list(self._connection_stats.values())
            
            if sort_by == "byte_count":
                connections.sort(key=lambda c: c.byte_count, reverse=True)
            elif sort_by == "packet_count":
                connections.sort(key=lambda c: c.packet_count, reverse=True)
            elif sort_by == "duration":
                connections.sort(key=lambda c: c.duration, reverse=True)
            
            return connections[:n]
    
    def get_sessions(
        self,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        port_range: Optional[Tuple[int, int]] = None,
        app_protocol: Optional[str] = None,
        sort_by: str = "byte_count",
        limit: Optional[int] = None,
    ) -> List[ConnectionStats]:
        """
        获取会话列表，支持按条件筛选
        
        Args:
            protocol: 传输层协议筛选 ("tcp" 或 "udp")
            port: 端口筛选（源或目的端口匹配）
            port_range: 端口范围筛选 (min_port, max_port)
            app_protocol: 应用层协议筛选
            sort_by: 排序字段 (byte_count, packet_count, duration, start_time)
            limit: 返回数量限制
        
        Returns:
            List[ConnectionStats]: 筛选后的会话列表
        """
        from network_analyzer.utils.packet_utils import IP_PROTO_TCP, IP_PROTO_UDP
        
        with self._lock:
            connections = list(self._connection_stats.values())
            
            if protocol:
                proto_lower = protocol.lower()
                if proto_lower == "tcp":
                    connections = [c for c in connections if c.five_tuple[4] == IP_PROTO_TCP]
                elif proto_lower == "udp":
                    connections = [c for c in connections if c.five_tuple[4] == IP_PROTO_UDP]
            
            if port is not None:
                connections = [
                    c for c in connections
                    if c.five_tuple[1] == port or c.five_tuple[3] == port
                ]
            
            if port_range:
                min_p, max_p = port_range
                connections = [
                    c for c in connections
                    if min_p <= c.five_tuple[1] <= max_p
                    or min_p <= c.five_tuple[3] <= max_p
                ]
            
            if app_protocol:
                connections = [
                    c for c in connections
                    if c.app_protocol and c.app_protocol.lower() == app_protocol.lower()
                ]
            
            if sort_by == "byte_count":
                connections.sort(key=lambda c: c.byte_count, reverse=True)
            elif sort_by == "packet_count":
                connections.sort(key=lambda c: c.packet_count, reverse=True)
            elif sort_by == "duration":
                connections.sort(key=lambda c: c.duration, reverse=True)
            elif sort_by == "start_time":
                connections.sort(key=lambda c: c.start_time)
            
            if limit:
                connections = connections[:limit]
            
            return connections
    
    def export_sessions_json(
        self,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        port_range: Optional[Tuple[int, int]] = None,
        app_protocol: Optional[str] = None,
        sort_by: str = "byte_count",
        limit: Optional[int] = None,
        pretty: bool = True,
    ) -> str:
        """
        导出会话明细为JSON格式
        
        Args:
            protocol: 传输层协议筛选 ("tcp" 或 "udp")
            port: 端口筛选
            port_range: 端口范围筛选 (min_port, max_port)
            app_protocol: 应用层协议筛选
            sort_by: 排序字段
            limit: 返回数量限制
            pretty: 是否格式化输出
        
        Returns:
            str: JSON格式的会话列表
        """
        sessions = self.get_sessions(
            protocol=protocol,
            port=port,
            port_range=port_range,
            app_protocol=app_protocol,
            sort_by=sort_by,
            limit=limit,
        )
        
        from network_analyzer.utils.packet_utils import IP_PROTO_TCP
        
        result = []
        for conn in sessions:
            result.append({
                "src_ip": conn.five_tuple[0],
                "src_port": conn.five_tuple[1],
                "dst_ip": conn.five_tuple[2],
                "dst_port": conn.five_tuple[3],
                "protocol": "TCP" if conn.five_tuple[4] == IP_PROTO_TCP else "UDP",
                "start_time": conn.start_time,
                "end_time": conn.last_time,
                "duration": round(conn.duration, 6),
                "packet_count": conn.packet_count,
                "byte_count": conn.byte_count,
                "client_packets": conn.client_packets,
                "server_packets": conn.server_packets,
                "client_bytes": conn.client_bytes,
                "server_bytes": conn.server_bytes,
                "app_protocol": conn.app_protocol,
                "state": conn.state,
            })
        
        indent = 2 if pretty else None
        return json.dumps(result, indent=indent, default=str)
    
    def export_sessions_csv(
        self,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        port_range: Optional[Tuple[int, int]] = None,
        app_protocol: Optional[str] = None,
        sort_by: str = "byte_count",
        limit: Optional[int] = None,
    ) -> str:
        """
        导出会话明细为CSV格式
        
        Args:
            protocol: 传输层协议筛选
            port: 端口筛选
            port_range: 端口范围筛选
            app_protocol: 应用层协议筛选
            sort_by: 排序字段
            limit: 返回数量限制
        
        Returns:
            str: CSV格式的会话列表
        """
        sessions = self.get_sessions(
            protocol=protocol,
            port=port,
            port_range=port_range,
            app_protocol=app_protocol,
            sort_by=sort_by,
            limit=limit,
        )
        
        from network_analyzer.utils.packet_utils import IP_PROTO_TCP
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "start_time", "end_time", "duration",
            "packet_count", "byte_count",
            "client_packets", "server_packets",
            "client_bytes", "server_bytes",
            "app_protocol", "state"
        ])
        
        for conn in sessions:
            proto = "TCP" if conn.five_tuple[4] == IP_PROTO_TCP else "UDP"
            writer.writerow([
                conn.five_tuple[0], conn.five_tuple[1],
                conn.five_tuple[2], conn.five_tuple[3],
                proto,
                conn.start_time, conn.last_time,
                round(conn.duration, 6),
                conn.packet_count, conn.byte_count,
                conn.client_packets, conn.server_packets,
                conn.client_bytes, conn.server_bytes,
                conn.app_protocol, conn.state
            ])
        
        return output.getvalue()
    
    def get_top_hosts(self, n: int = 10, sort_by: str = "total_bytes") -> List[HostStats]:
        """
        获取Top N主机
        
        Args:
            n: 返回数量
            sort_by: 排序字段 (total_bytes, total_packets)
        
        Returns:
            List[HostStats]: 排序后的主机统计列表
        """
        with self._lock:
            hosts = list(self._host_stats.values())
            
            if sort_by == "total_bytes":
                hosts.sort(key=lambda h: h.total_bytes, reverse=True)
            elif sort_by == "total_packets":
                hosts.sort(key=lambda h: h.total_packets, reverse=True)
            elif sort_by == "bytes_sent":
                hosts.sort(key=lambda h: h.bytes_sent, reverse=True)
            elif sort_by == "bytes_received":
                hosts.sort(key=lambda h: h.bytes_received, reverse=True)
            
            return hosts[:n]
    
    def get_top_ports(self, n: int = 10, protocol: str = "tcp") -> List[Tuple[int, ProtocolStats]]:
        """
        获取Top N端口
        
        Args:
            n: 返回数量
            protocol: "tcp" 或 "udp"
        
        Returns:
            List[Tuple[int, ProtocolStats]]: (端口号, 统计信息) 列表
        """
        with self._lock:
            if protocol.lower() == "tcp":
                ports = list(self._tcp_port_stats.items())
            else:
                ports = list(self._udp_port_stats.items())
            
            ports.sort(key=lambda x: x[1].byte_count, reverse=True)
            return ports[:n]
    
    def get_time_series(self) -> Dict[str, Any]:
        """
        获取时间序列数据
        
        Returns:
            包含时间戳、包数、字节数，以及TCP/UDP/应用协议分布的字典
        """
        from network_analyzer.utils.packet_utils import IP_PROTO_NAME
        
        with self._lock:
            tw = self._time_window
            return {
                "window_seconds": tw.window_seconds,
                "timestamps": list(tw.timestamps),
                "packet_counts": list(tw.packet_counts),
                "byte_counts": list(tw.byte_counts),
                "tcp_packets": list(tw.tcp_packets),
                "tcp_bytes": list(tw.tcp_bytes),
                "udp_packets": list(tw.udp_packets),
                "udp_bytes": list(tw.udp_bytes),
                "app_protocol_packets": [dict(d) for d in tw.app_protocol_packets],
                "app_protocol_bytes": [dict(d) for d in tw.app_protocol_bytes],
            }
    
    def set_time_window(self, window_seconds: int):
        """
        设置时间窗口大小（会重置现有窗口数据）
        
        Args:
            window_seconds: 窗口大小（秒）
        """
        with self._lock:
            self._time_window = TimeWindowStats(window_seconds=window_seconds)
    
    def get_summary(self) -> Dict[str, Any]:
        """获取统计摘要"""
        with self._lock:
            g = self._global
            
            summary = {
                "total_packets": g.total_packets,
                "total_bytes": g.total_bytes,
                "duration": g.duration,
                "avg_packet_size": g.avg_packet_size,
                "packets_per_second": g.packets_per_second,
                "bytes_per_second": g.bytes_per_second,
                "truncated_packets": g.truncated_packets,
                "error_packets": g.error_packets,
                "ethertype_count": len(self._ethertype_stats),
                "ip_proto_count": len(self._ip_proto_stats),
                "app_proto_count": len(self._app_proto_stats),
                "connection_count": len(self._connection_stats),
                "host_count": len(self._host_stats),
            }
            
            return summary
    
    def export_json(self, pretty: bool = True) -> str:
        """
        导出所有统计为JSON格式
        
        Args:
            pretty: 是否格式化输出
            
        Returns:
            str: JSON格式的统计数据
        """
        with self._lock:
            data = {}
            
            g = self._global
            data["global"] = {
                "total_packets": g.total_packets,
                "total_bytes": g.total_bytes,
                "truncated_packets": g.truncated_packets,
                "error_packets": g.error_packets,
                "start_time": g.start_time,
                "last_packet_time": g.last_packet_time,
                "duration": g.duration,
                "avg_packet_size": g.avg_packet_size,
                "packets_per_second": g.packets_per_second,
                "bytes_per_second": g.bytes_per_second,
                "min_packet_size": g.min_packet_size,
                "max_packet_size": g.max_packet_size,
                "total_payload_bytes": g.total_payload_bytes,
            }
            
            from network_analyzer.utils.packet_utils import ETHERTYPE_NAME, IP_PROTO_NAME
            
            data["ethernet_protocols"] = {}
            for eth_type, stats in self._ethertype_stats.items():
                name = ETHERTYPE_NAME.get(eth_type, f"0x{eth_type:04x}")
                data["ethernet_protocols"][name] = {
                    "packet_count": stats.packet_count,
                    "byte_count": stats.byte_count,
                }
            
            data["ip_protocols"] = {}
            for proto, stats in self._ip_proto_stats.items():
                name = IP_PROTO_NAME.get(proto, str(proto))
                data["ip_protocols"][name] = {
                    "packet_count": stats.packet_count,
                    "byte_count": stats.byte_count,
                }
            
            data["application_protocols"] = {}
            for proto, stats in self._app_proto_stats.items():
                data["application_protocols"][proto] = {
                    "packet_count": stats.packet_count,
                    "byte_count": stats.byte_count,
                }
            
            data["connections"] = []
            for conn in sorted(
                self._connection_stats.values(),
                key=lambda c: c.byte_count,
                reverse=True
            ):
                data["connections"].append({
                    "src_ip": conn.five_tuple[0],
                    "src_port": conn.five_tuple[1],
                    "dst_ip": conn.five_tuple[2],
                    "dst_port": conn.five_tuple[3],
                    "protocol": "TCP" if conn.five_tuple[4] == 6 else "UDP",
                    "packet_count": conn.packet_count,
                    "byte_count": conn.byte_count,
                    "client_packets": conn.client_packets,
                    "server_packets": conn.server_packets,
                    "client_bytes": conn.client_bytes,
                    "server_bytes": conn.server_bytes,
                    "start_time": conn.start_time,
                    "last_time": conn.last_time,
                    "duration": conn.duration,
                    "state": conn.state,
                    "app_protocol": conn.app_protocol,
                })
            
            data["hosts"] = []
            for host in sorted(
                self._host_stats.values(),
                key=lambda h: h.total_bytes,
                reverse=True
            ):
                data["hosts"].append({
                    "ip": host.ip,
                    "packets_sent": host.packets_sent,
                    "packets_received": host.packets_received,
                    "total_packets": host.total_packets,
                    "bytes_sent": host.bytes_sent,
                    "bytes_received": host.bytes_received,
                    "total_bytes": host.total_bytes,
                    "connections": host.connections,
                })
            
            data["tcp_ports"] = {}
            for port, stats in sorted(
                self._tcp_port_stats.items(),
                key=lambda x: x[1].byte_count,
                reverse=True
            ):
                data["tcp_ports"][port] = {
                    "packet_count": stats.packet_count,
                    "byte_count": stats.byte_count,
                }
            
            data["udp_ports"] = {}
            for port, stats in sorted(
                self._udp_port_stats.items(),
                key=lambda x: x[1].byte_count,
                reverse=True
            ):
                data["udp_ports"][port] = {
                    "packet_count": stats.packet_count,
                    "byte_count": stats.byte_count,
                }
            
            data["time_series"] = {
                "window_seconds": self._time_window.window_seconds,
                "timestamps": list(self._time_window.timestamps),
                "packet_counts": list(self._time_window.packet_counts),
                "byte_counts": list(self._time_window.byte_counts),
                "tcp_packets": list(self._time_window.tcp_packets),
                "tcp_bytes": list(self._time_window.tcp_bytes),
                "udp_packets": list(self._time_window.udp_packets),
                "udp_bytes": list(self._time_window.udp_bytes),
                "app_protocol_packets": [dict(d) for d in self._time_window.app_protocol_packets],
                "app_protocol_bytes": [dict(d) for d in self._time_window.app_protocol_bytes],
            }
            
            indent = 2 if pretty else None
            return json.dumps(data, indent=indent, default=str)
    
    def export_csv(self, section: str = "all") -> Dict[str, str]:
        """
        导出统计为CSV格式
        
        Args:
            section: 导出的部分 ("all", "connections", "hosts", 
                     "app_protocols", "tcp_ports", "udp_ports", "time_series")
            
        Returns:
            Dict[str, str]: 各部分对应的CSV字符串
        """
        with self._lock:
            result = {}
            
            sections = [section] if section != "all" else [
                "connections", "hosts", "app_protocols", 
                "tcp_ports", "udp_ports", "time_series",
            ]
            
            if "connections" in sections:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow([
                    "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                    "packet_count", "byte_count", "client_packets", "server_packets",
                    "client_bytes", "server_bytes", "duration", "state", "app_protocol"
                ])
                for conn in sorted(
                    self._connection_stats.values(),
                    key=lambda c: c.byte_count,
                    reverse=True
                ):
                    proto = "TCP" if conn.five_tuple[4] == 6 else "UDP"
                    writer.writerow([
                        conn.five_tuple[0], conn.five_tuple[1],
                        conn.five_tuple[2], conn.five_tuple[3],
                        proto, conn.packet_count, conn.byte_count,
                        conn.client_packets, conn.server_packets,
                        conn.client_bytes, conn.server_bytes,
                        round(conn.duration, 6), conn.state, conn.app_protocol
                    ])
                result["connections"] = output.getvalue()
            
            if "hosts" in sections:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow([
                    "ip", "packets_sent", "packets_received", "total_packets",
                    "bytes_sent", "bytes_received", "total_bytes", "connections"
                ])
                for host in sorted(
                    self._host_stats.values(),
                    key=lambda h: h.total_bytes,
                    reverse=True
                ):
                    writer.writerow([
                        host.ip, host.packets_sent, host.packets_received,
                        host.total_packets, host.bytes_sent, host.bytes_received,
                        host.total_bytes, host.connections
                    ])
                result["hosts"] = output.getvalue()
            
            if "app_protocols" in sections:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["protocol", "packet_count", "byte_count"])
                for proto, stats in sorted(
                    self._app_proto_stats.items(),
                    key=lambda x: x[1].byte_count,
                    reverse=True
                ):
                    writer.writerow([proto, stats.packet_count, stats.byte_count])
                result["app_protocols"] = output.getvalue()
            
            if "tcp_ports" in sections:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["port", "packet_count", "byte_count"])
                for port, stats in sorted(
                    self._tcp_port_stats.items(),
                    key=lambda x: x[1].byte_count,
                    reverse=True
                ):
                    writer.writerow([port, stats.packet_count, stats.byte_count])
                result["tcp_ports"] = output.getvalue()
            
            if "udp_ports" in sections:
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["port", "packet_count", "byte_count"])
                for port, stats in sorted(
                    self._udp_port_stats.items(),
                    key=lambda x: x[1].byte_count,
                    reverse=True
                ):
                    writer.writerow([port, stats.packet_count, stats.byte_count])
                result["udp_ports"] = output.getvalue()
            
            if "time_series" in sections:
                tw = self._time_window
                all_app_protos = set()
                for d in tw.app_protocol_packets:
                    all_app_protos.update(d.keys())
                app_proto_list = sorted(all_app_protos)
                
                output = io.StringIO()
                writer = csv.writer(output)
                header = [
                    "timestamp", "packet_count", "byte_count",
                    "tcp_packets", "tcp_bytes",
                    "udp_packets", "udp_bytes"
                ]
                for ap in app_proto_list:
                    header.append(f"{ap}_packets")
                    header.append(f"{ap}_bytes")
                writer.writerow(header)
                
                for i in range(len(tw.timestamps)):
                    row = [
                        tw.timestamps[i],
                        tw.packet_counts[i],
                        tw.byte_counts[i],
                        tw.tcp_packets[i],
                        tw.tcp_bytes[i],
                        tw.udp_packets[i],
                        tw.udp_bytes[i],
                    ]
                    for ap in app_proto_list:
                        row.append(tw.app_protocol_packets[i].get(ap, 0))
                        row.append(tw.app_protocol_bytes[i].get(ap, 0))
                    writer.writerow(row)
                result["time_series"] = output.getvalue()
            
            return result
    
    def reset(self):
        """重置所有统计"""
        with self._lock:
            self._global.reset()
            self._ethertype_stats.clear()
            self._ip_proto_stats.clear()
            self._app_proto_stats.clear()
            self._connection_stats.clear()
            self._host_stats.clear()
            self._tcp_port_stats.clear()
            self._udp_port_stats.clear()
            self._time_window.reset()
