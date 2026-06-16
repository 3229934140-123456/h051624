"""
网络协议分析器主入口
======================
整合各模块，提供完整的协议解析与分析功能。

完整的解析流程:
1. 链路层: 解析以太网帧 -> 提取payload -> 判断网络层协议
2. 网络层: 解析IP数据包 -> 分片重组 -> 判断传输层协议
3. 传输层: 解析TCP/UDP -> TCP流重组 -> 判断应用层协议
4. 应用层: 协议识别 -> 应用数据解析
5. 过滤统计: 应用过滤规则 -> 统计分析

五元组连接跟踪:
- 使用 (src_ip, src_port, dst_ip, dst_port, protocol) 唯一标识一个连接
- 正向和反向数据包映射到同一个连接
- 跟踪连接状态 (SYN, ESTABLISHED, FIN_WAIT, CLOSED等)

截断/损坏包处理:
- 每层解析时检查数据长度是否足够
- 截断包标记 is_truncated 并记录错误信息
- 损坏包继续尝试解析可用部分，不中断整个流程
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Callable, Any
from collections import defaultdict

from .layers.link_layer import EthernetFrame, parse_ethernet
from .layers.network_layer import IPPacket, parse_ipv4
from .layers.transport_layer import TCPSegment, UDPPacket, parse_tcp, parse_udp

from .stream.ip_reassembly import IPReassembler
from .stream.tcp_reassembly import TCPStreamReassembler, TCPConnection, get_five_tuple_key

from .application.protocol_identification import (
    AppProtocolIdentifier,
    ProtocolIdentificationResult,
    AppProtocol,
)

from .filter.filter import PacketFilter, FilterContext

from .stats.statistics import StatisticsCollector


@dataclass
class ParsedPacket:
    """完整解析的数据包"""
    timestamp: float = 0.0
    packet_number: int = 0
    
    ethernet: Optional[EthernetFrame] = None
    ip: Optional[IPPacket] = None
    tcp: Optional[TCPSegment] = None
    udp: Optional[UDPPacket] = None
    
    app_protocol: str = "unknown"
    app_data: bytes = b""
    
    is_fragment: bool = False
    is_reassembled: bool = False
    
    five_tuple: Optional[Tuple] = None
    
    parse_errors: List[str] = field(default_factory=list)
    
    def summary(self) -> str:
        """获取数据包摘要"""
        parts = [f"#{self.packet_number}"]
        
        if self.ethernet:
            parts.append(f"ETH {self.ethernet.ethertype_name}")
        
        if self.ip:
            parts.append(f"IP {self.ip.header.protocol_name}")
            parts.append(f"{self.ip.header.src_ip} -> {self.ip.header.dst_ip}")
        elif self.ethernet:
            parts.append(f"{self.ethernet.src_mac} -> {self.ethernet.dst_mac}")
        
        if self.tcp:
            parts.append(f"TCP {self.tcp.src_port} -> {self.tcp.dst_port}")
            parts.append(f"seq={self.tcp.seq} flags=[{self.tcp.flags_str}] len={self.tcp.payload_length}")
        elif self.udp:
            parts.append(f"UDP {self.udp.src_port} -> {self.udp.dst_port}")
            parts.append(f"len={self.udp.length}")
        
        if self.app_protocol != "unknown":
            parts.append(f"app={self.app_protocol}")
        
        if self.is_fragment:
            parts.append("[FRAGMENT]")
        if self.is_reassembled:
            parts.append("[REASSEMBLED]")
        
        if self.parse_errors:
            parts.append(f"[ERRORS: {len(self.parse_errors)}]")
        
        return " ".join(parts)


@dataclass
class StreamData:
    """TCP流重组后的数据"""
    five_tuple: Tuple
    client_to_server: bytes = b""
    server_to_client: bytes = b""
    app_protocol: str = "unknown"
    app_protocol_method: str = "unknown"
    app_protocol_confidence: float = 0.0


class NetworkAnalyzer:
    """
    网络协议分析器
    
    整合所有模块，提供完整的协议分析功能。
    
    使用方法:
        analyzer = NetworkAnalyzer()
        
        # 处理单个数据包
        parsed = analyzer.analyze(frame_data, timestamp)
        
        # 获取统计信息
        stats = analyzer.get_statistics()
        
        # 获取流数据
        streams = analyzer.get_all_streams()
    """
    
    def __init__(self, enable_reassembly: bool = True):
        """
        初始化网络协议分析器
        
        Args:
            enable_reassembly: 是否启用IP分片重组和TCP流重组
        """
        self.enable_reassembly = enable_reassembly
        
        self._packet_count = 0
        self._lock = threading.Lock()
        
        self._ip_reassembler = IPReassembler(timeout=30.0)
        self._tcp_reassembler = TCPStreamReassembler(timeout=300.0)
        self._app_identifier = AppProtocolIdentifier()
        self._filter: Optional[PacketFilter] = None
        self._stats = StatisticsCollector()
        
        self._stream_data: Dict[Tuple, StreamData] = {}
        
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
    
    def analyze(
        self,
        frame_data: bytes,
        timestamp: Optional[float] = None,
    ) -> Optional[ParsedPacket]:
        """
        分析一个以太网帧
        
        逐层剥离协议头的完整过程:
        1. 链路层: 解析以太网帧头，获取以太类型和payload
        2. 网络层: 根据以太类型解析IP头，获取协议号和payload
           - 如果是分片，加入IP分片重组缓冲区
           - 如果重组完成，继续解析重组后的完整IP包
        3. 传输层: 根据协议号解析TCP/UDP头，获取端口和payload
           - 如果是TCP，加入TCP流重组缓冲区
           - 如果有连续数据交付，继续应用层识别
        4. 应用层: 基于端口和数据特征识别应用协议
        5. 过滤和统计: 应用过滤规则，更新统计信息
        
        Args:
            frame_data: 原始以太网帧数据
            timestamp: 时间戳(秒)，默认当前时间
        
        Returns:
            ParsedPacket: 解析后的数据包对象
                         如果被过滤掉返回None
        """
        if timestamp is None:
            timestamp = time.time()
        
        with self._lock:
            self._packet_count += 1
            
            parsed = ParsedPacket(
                timestamp=timestamp,
                packet_number=self._packet_count,
            )
            
            try:
                self._parse_layer2(frame_data, parsed)
                
                if parsed.ethernet and parsed.ethernet.ethertype == 0x0800:
                    self._parse_layer3(parsed)
                
                if parsed.ip and not parsed.is_fragment:
                    self._parse_layer4(parsed)
                
                if parsed.tcp or parsed.udp:
                    self._parse_layer7(parsed)
                
                self._compute_five_tuple(parsed)
                
                filter_ctx = self._make_filter_context(parsed)
                if self._filter and not self._filter.match(filter_ctx):
                    return None
                
                self._stats.record_packet(filter_ctx, timestamp)
                
                self._trigger_callbacks("packet", parsed)
                
                return parsed
                
            except Exception as e:
                parsed.parse_errors.append(f"Fatal error: {e}")
                return parsed
    
    def _parse_layer2(self, frame_data: bytes, parsed: ParsedPacket):
        """解析链路层"""
        ether = parse_ethernet(frame_data)
        parsed.ethernet = ether
        
        if ether.is_truncated:
            parsed.parse_errors.append(f"Ethernet truncated: {ether.parse_error or 'unknown'}")
        if ether.parse_error:
            parsed.parse_errors.append(f"Ethernet error: {ether.parse_error}")
    
    def _parse_layer3(self, parsed: ParsedPacket):
        """解析网络层"""
        if not parsed.ethernet:
            return
        
        ip_packet = parse_ipv4(parsed.ethernet.payload)
        parsed.ip = ip_packet
        
        if ip_packet.is_truncated:
            parsed.parse_errors.append(f"IP truncated: {ip_packet.parse_error or 'unknown'}")
        if ip_packet.parse_error:
            parsed.parse_errors.append(f"IP error: {ip_packet.parse_error}")
        
        if ip_packet.is_fragmented:
            parsed.is_fragment = True
            
            if self.enable_reassembly:
                reassembled = self._ip_reassembler.process(ip_packet)
                if reassembled is not None:
                    parsed.ip = reassembled
                    parsed.is_reassembled = True
                    parsed.is_fragment = False
                else:
                    return
            else:
                return
        
        if not ip_packet.is_fragmented or parsed.is_reassembled:
            pass
    
    def _parse_layer4(self, parsed: ParsedPacket):
        """解析传输层"""
        if not parsed.ip:
            return
        
        proto = parsed.ip.header.protocol
        payload = parsed.ip.payload
        
        if proto == 6:
            tcp = parse_tcp(
                payload,
                parsed.ip.header.src_ip,
                parsed.ip.header.dst_ip
            )
            parsed.tcp = tcp
            
            if tcp.is_truncated:
                parsed.parse_errors.append(f"TCP truncated: {tcp.parse_error or 'unknown'}")
            if tcp.parse_error:
                parsed.parse_errors.append(f"TCP error: {tcp.parse_error}")
            
            if self.enable_reassembly and not parsed.is_fragment:
                self._handle_tcp_reassembly(parsed)
        
        elif proto == 17:
            udp = parse_udp(
                payload,
                parsed.ip.header.src_ip,
                parsed.ip.header.dst_ip
            )
            parsed.udp = udp
            
            if udp.is_truncated:
                parsed.parse_errors.append(f"UDP truncated: {udp.parse_error or 'unknown'}")
            if udp.parse_error:
                parsed.parse_errors.append(f"UDP error: {udp.parse_error}")
    
    def _handle_tcp_reassembly(self, parsed: ParsedPacket):
        """处理TCP流重组"""
        if not parsed.ip or not parsed.tcp:
            return
        
        src_ip, src_port, dst_ip, dst_port, c2s_data, s2c_data = (
            self._tcp_reassembler.process(parsed.ip, parsed.tcp)
        )
        
        five_tuple = get_five_tuple_key(
            src_ip, src_port, dst_ip, dst_port, 6
        )
        
        if five_tuple not in self._stream_data:
            self._stream_data[five_tuple] = StreamData(five_tuple=five_tuple)
        
        stream = self._stream_data[five_tuple]
        
        if c2s_data:
            stream.client_to_server += c2s_data
            self._identify_app_protocol(stream, c2s_data, True)
        
        if s2c_data:
            stream.server_to_client += s2c_data
            self._identify_app_protocol(stream, s2c_data, False)
    
    def _parse_layer7(self, parsed: ParsedPacket):
        """初步识别应用层协议 (基于端口和首个数据包)"""
        src_port = 0
        dst_port = 0
        payload = b""
        
        if parsed.tcp:
            src_port = parsed.tcp.src_port
            dst_port = parsed.tcp.dst_port
            payload = parsed.tcp.payload
        elif parsed.udp:
            src_port = parsed.udp.src_port
            dst_port = parsed.udp.dst_port
            payload = parsed.udp.payload
        
        if src_port or dst_port:
            is_tcp = parsed.tcp is not None
            try:
                result = self._app_identifier.identify(
                    payload,
                    src_port,
                    dst_port,
                    is_tcp
                )
                parsed.app_protocol = result.protocol.value
            except Exception:
                parsed.app_protocol = "unknown"
            parsed.app_data = payload
    
    def _identify_app_protocol(
        self,
        stream: StreamData,
        new_data: bytes,
        is_client_to_server: bool,
    ):
        """识别应用层协议 (基于重组后的流数据)"""
        if stream.app_protocol != "unknown" and stream.app_protocol_method == "confirmed":
            return
        
        data = stream.client_to_server if is_client_to_server else stream.server_to_client
        
        if not data:
            return
        
        client_port = stream.five_tuple[1]
        server_port = stream.five_tuple[3]
        
        if is_client_to_server:
            src_port, dst_port = client_port, server_port
        else:
            src_port, dst_port = server_port, client_port
        
        try:
            result = self._app_identifier.identify(
                new_data,
                src_port,
                dst_port,
                True,
                stream.five_tuple,
            )
            
            if result.confidence > 0.6:
                stream.app_protocol = result.protocol.value
                stream.app_protocol_method = result.method.value
                stream.app_protocol_confidence = result.confidence
        except Exception:
            pass
    
    def _compute_five_tuple(self, parsed: ParsedPacket):
        """计算五元组"""
        if not parsed.ip:
            return
        
        src_ip = parsed.ip.header.src_ip
        dst_ip = parsed.ip.header.dst_ip
        proto = parsed.ip.header.protocol
        
        src_port = 0
        dst_port = 0
        
        if parsed.tcp:
            src_port = parsed.tcp.src_port
            dst_port = parsed.tcp.dst_port
        elif parsed.udp:
            src_port = parsed.udp.src_port
            dst_port = parsed.udp.dst_port
        else:
            return
        
        parsed.five_tuple = get_five_tuple_key(
            src_ip, src_port, dst_ip, dst_port, proto
        )
    
    def _make_filter_context(self, parsed: ParsedPacket) -> FilterContext:
        """创建过滤上下文"""
        ctx = FilterContext()
        ctx.ethernet = parsed.ethernet
        ctx.ip = parsed.ip
        ctx.tcp = parsed.tcp
        ctx.udp = parsed.udp
        ctx.app_protocol = parsed.app_protocol
        return ctx
    
    def set_filter(self, expression: str):
        """设置过滤表达式"""
        self._filter = PacketFilter(expression)
    
    def clear_filter(self):
        """清除过滤规则"""
        self._filter = None
    
    def get_statistics(self) -> Dict:
        """获取统计摘要"""
        return self._stats.get_summary()
    
    def get_detailed_stats(self):
        """获取详细统计信息"""
        return {
            "global": self._stats.get_global_stats(),
            "ethertypes": self._stats.get_ethertype_stats(),
            "ip_protocols": self._stats.get_ip_proto_stats(),
            "app_protocols": self._stats.get_app_proto_stats(),
            "connections": self._stats.get_connection_stats(),
            "hosts": self._stats.get_top_hosts(10),
            "tcp_ports": self._stats.get_top_ports(10, "tcp"),
            "udp_ports": self._stats.get_top_ports(10, "udp"),
            "time_series": self._stats.get_time_series(),
        }
    
    def get_all_streams(self) -> List[StreamData]:
        """获取所有TCP流"""
        with self._lock:
            return list(self._stream_data.values())
    
    def get_stream(self, five_tuple: Tuple) -> Optional[StreamData]:
        """获取指定的TCP流"""
        with self._lock:
            return self._stream_data.get(five_tuple)
    
    def get_tcp_connections(self) -> List[TCPConnection]:
        """获取所有TCP连接"""
        return self._tcp_reassembler.get_all_connections()
    
    def get_packet_count(self) -> int:
        """获取处理的数据包总数"""
        return self._packet_count
    
    def add_callback(self, event: str, callback: Callable):
        """
        添加事件回调
        
        支持的事件:
        - "packet": 每个解析完成的数据包
        """
        self._callbacks[event].append(callback)
    
    def remove_callback(self, event: str, callback: Callable):
        """移除事件回调"""
        if callback in self._callbacks[event]:
            self._callbacks[event].remove(callback)
    
    def _trigger_callbacks(self, event: str, *args, **kwargs):
        """触发事件回调"""
        for cb in self._callbacks[event]:
            try:
                cb(*args, **kwargs)
            except Exception:
                pass
    
    def reset(self):
        """重置分析器状态"""
        with self._lock:
            self._packet_count = 0
            self._ip_reassembler.reset()
            self._tcp_reassembler.reset()
            self._app_identifier.reset()
            self._stats.reset()
            self._stream_data.clear()


__all__ = [
    "NetworkAnalyzer",
    "ParsedPacket",
    "StreamData",
]
