"""
测试用例
=========
验证网络协议分析器各模块的功能。

运行方式:
    python -m tests.test_analyzer
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network_analyzer.layers.link_layer import (
    parse_ethernet,
    build_ethernet,
    EthernetFrame,
    ETHERTYPE_IPV4,
)
from network_analyzer.layers.network_layer import (
    parse_ipv4,
    build_ipv4,
    IPPacket,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
)
from network_analyzer.layers.transport_layer import (
    parse_tcp,
    parse_udp,
    build_tcp,
    build_udp,
    TCPSegment,
    UDPPacket,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_PSH,
)
from network_analyzer.stream.ip_reassembly import (
    IPReassembler,
    fragment_ip_packet,
)
from network_analyzer.stream.tcp_reassembly import (
    TCPStreamReassembler,
    TCPConnection,
    get_five_tuple_key,
)
from network_analyzer.application.protocol_identification import (
    AppProtocolIdentifier,
    AppProtocol,
    identify_protocol,
)
from network_analyzer.filter.filter import (
    PacketFilter,
    FilterContext,
)
from network_analyzer.stats.statistics import (
    StatisticsCollector,
)
from network_analyzer.analyzer import (
    NetworkAnalyzer,
    ParsedPacket,
)


def _build_full_frame(
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
    tcp_flags: int = TCP_FLAG_ACK,
    is_tcp: bool = True,
) -> bytes:
    """构建完整的以太网帧 (用于测试)"""
    if is_tcp:
        transport = build_tcp(
            src_port, dst_port, seq=1000, ack=2000,
            flags=tcp_flags, payload=payload,
            src_ip=src_ip, dst_ip=dst_ip
        )
        proto = IP_PROTO_TCP
    else:
        transport = build_udp(
            src_port, dst_port, payload=payload,
            src_ip=src_ip, dst_ip=dst_ip
        )
        proto = IP_PROTO_UDP
    
    ip = build_ipv4(src_ip, dst_ip, proto, transport)
    ether = build_ethernet(dst_mac, src_mac, ETHERTYPE_IPV4, ip)
    
    return ether


class TestLinkLayer(unittest.TestCase):
    """链路层解析测试"""
    
    def test_parse_ethernet(self):
        frame = build_ethernet(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            ETHERTYPE_IPV4,
            b"\x00" * 100
        )
        
        result = parse_ethernet(frame)
        
        self.assertEqual(result.dst_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result.src_mac, "11:22:33:44:55:66")
        self.assertEqual(result.ethertype, ETHERTYPE_IPV4)
        self.assertEqual(len(result.payload), 100)
        self.assertFalse(result.is_truncated)
        self.assertIsNone(result.parse_error)
    
    def test_ethernet_truncated(self):
        frame = b"\x00" * 10
        result = parse_ethernet(frame)
        self.assertTrue(result.is_truncated)
        self.assertIsNotNone(result.parse_error)
    
    def test_vlan_frame(self):
        frame = build_ethernet(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            0x8100,
            b"\x00" * 4 + b"\x00" * 100
        )
        result = parse_ethernet(frame)
        self.assertEqual(result.ethertype, 0x0000)
    
    def test_ethertype_name(self):
        frame = build_ethernet("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4, b"")
        result = parse_ethernet(frame)
        self.assertEqual(result.ethertype_name, "IPv4")
    
    def test_summary(self):
        frame = build_ethernet("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4, b"\x00" * 50)
        result = parse_ethernet(frame)
        summary = result.summary()
        self.assertIn("Ethernet", summary)
        self.assertIn("IPv4", summary)


class TestNetworkLayer(unittest.TestCase):
    """网络层解析测试"""
    
    def test_parse_ipv4(self):
        payload = b"\x00" * 50
        packet = build_ipv4("192.168.1.1", "10.0.0.1", IP_PROTO_TCP, payload)
        
        result = parse_ipv4(packet)
        
        self.assertEqual(result.header.version, 4)
        self.assertEqual(result.header.src_ip, "192.168.1.1")
        self.assertEqual(result.header.dst_ip, "10.0.0.1")
        self.assertEqual(result.header.protocol, IP_PROTO_TCP)
        self.assertEqual(len(result.payload), 50)
        self.assertFalse(result.is_fragmented)
        self.assertFalse(result.is_truncated)
    
    def test_ip_checksum(self):
        payload = b"test payload"
        packet = build_ipv4("1.2.3.4", "5.6.7.8", IP_PROTO_TCP, payload)
        result = parse_ipv4(packet)
        self.assertTrue(result.checksum_valid)
    
    def test_ip_fragmented(self):
        payload = b"\x00" * 100
        packet = build_ipv4(
            "1.1.1.1", "2.2.2.2", IP_PROTO_TCP, payload,
            flags=0x2000, fragment_offset=100
        )
        result = parse_ipv4(packet)
        self.assertTrue(result.is_fragmented)
        self.assertTrue(result.header.mf_flag)
        self.assertEqual(result.header.fragment_offset, 100)
        self.assertEqual(result.header.fragment_offset_bytes, 800)
    
    def test_ip_truncated(self):
        packet = b"\x45\x00"
        result = parse_ipv4(packet)
        self.assertTrue(result.is_truncated)
    
    def test_not_ipv4(self):
        packet = b"\x60\x00" + b"\x00" * 18
        result = parse_ipv4(packet)
        self.assertIsNotNone(result.parse_error)


class TestTransportLayer(unittest.TestCase):
    """传输层解析测试"""
    
    def test_parse_tcp(self):
        payload = b"Hello TCP"
        segment = build_tcp(
            12345, 80, seq=1000, ack=2000,
            flags=TCP_FLAG_ACK | TCP_FLAG_PSH,
            payload=payload,
            src_ip="1.2.3.4", dst_ip="5.6.7.8"
        )
        
        result = parse_tcp(segment, "1.2.3.4", "5.6.7.8")
        
        self.assertEqual(result.src_port, 12345)
        self.assertEqual(result.dst_port, 80)
        self.assertEqual(result.seq, 1000)
        self.assertEqual(result.ack, 2000)
        self.assertTrue(result.ack_flag)
        self.assertTrue(result.psh)
        self.assertFalse(result.syn)
        self.assertEqual(result.payload, payload)
        self.assertEqual(result.payload_length, len(payload))
    
    def test_tcp_flags(self):
        segment = build_tcp(1, 2, flags=TCP_FLAG_SYN)
        result = parse_tcp(segment)
        self.assertTrue(result.syn)
        self.assertFalse(result.ack_flag)
        self.assertIn("SYN", result.flags_str)
    
    def test_tcp_checksum(self):
        payload = b"test data"
        segment = build_tcp(
            1000, 2000, payload=payload,
            src_ip="10.0.0.1", dst_ip="10.0.0.2"
        )
        result = parse_tcp(segment, "10.0.0.1", "10.0.0.2")
        self.assertTrue(result.checksum_valid)
    
    def test_parse_udp(self):
        payload = b"Hello UDP"
        packet = build_udp(
            53, 12345, payload=payload,
            src_ip="1.2.3.4", dst_ip="5.6.7.8"
        )
        
        result = parse_udp(packet, "1.2.3.4", "5.6.7.8")
        
        self.assertEqual(result.src_port, 53)
        self.assertEqual(result.dst_port, 12345)
        self.assertEqual(result.payload, payload)
        self.assertEqual(result.length, 8 + len(payload))
    
    def test_tcp_truncated(self):
        segment = b"\x00" * 10
        result = parse_tcp(segment)
        self.assertTrue(result.is_truncated)
        self.assertIsNotNone(result.parse_error)
    
    def test_tcp_seq_end(self):
        segment = build_tcp(
            1, 2, seq=100, flags=TCP_FLAG_SYN,
            payload=b"abc"
        )
        result = parse_tcp(segment)
        self.assertEqual(result.seq_end, 104)


class TestIPReassembly(unittest.TestCase):
    """IP分片重组测试"""
    
    def test_fragment_and_reassemble(self):
        payload = b"A" * 3000
        packet = build_ipv4(
            "1.1.1.1", "2.2.2.2", IP_PROTO_TCP, payload,
            identification=12345
        )
        
        fragments = fragment_ip_packet(packet, mtu=1000)
        self.assertGreater(len(fragments), 1)
        
        reassembler = IPReassembler()
        
        last_result = None
        for frag_data in fragments:
            frag_pkt = parse_ipv4(frag_data)
            result = reassembler.process(frag_pkt)
            if result is not None:
                last_result = result
        
        self.assertIsNotNone(last_result)
        self.assertEqual(len(last_result.payload), len(payload))
        self.assertEqual(last_result.payload, payload)
        self.assertFalse(last_result.is_fragmented)
    
    def test_fragment_out_of_order(self):
        payload = b"".join(bytes([i]) * 100 for i in range(10))
        packet = build_ipv4(
            "1.1.1.1", "2.2.2.2", IP_PROTO_UDP, payload,
            identification=999
        )
        
        fragments = fragment_ip_packet(packet, mtu=300)
        self.assertGreater(len(fragments), 2)
        
        reversed_fragments = list(reversed(fragments))
        
        reassembler = IPReassembler()
        last_result = None
        for frag_data in reversed_fragments:
            frag_pkt = parse_ipv4(frag_data)
            result = reassembler.process(frag_pkt)
            if result is not None:
                last_result = result
        
        self.assertIsNotNone(last_result)
        self.assertEqual(last_result.payload, payload)
    
    def test_no_fragment_passthrough(self):
        packet = build_ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_TCP, b"test")
        parsed = parse_ipv4(packet)
        
        reassembler = IPReassembler()
        result = reassembler.process(parsed)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.payload, parsed.payload)
    
    def test_reassembly_stats(self):
        reassembler = IPReassembler()
        stats = reassembler.get_stats()
        self.assertIn("total_fragments", stats)
        self.assertIn("reassembled_datagrams", stats)


class TestTCPReassembly(unittest.TestCase):
    """TCP流重组测试"""
    
    def setUp(self):
        self.src_ip = "10.0.0.1"
        self.dst_ip = "10.0.0.2"
        self.src_port = 12345
        self.dst_port = 80
    
    def _build_ip_tcp(self, seq, flags, payload, src_ip=None, dst_ip=None, src_port=None, dst_port=None):
        src_ip = src_ip or self.src_ip
        dst_ip = dst_ip or self.dst_ip
        src_port = src_port or self.src_port
        dst_port = dst_port or self.dst_port
        
        tcp = build_tcp(
            src_port, dst_port, seq=seq, ack=0,
            flags=flags, payload=payload,
            src_ip=src_ip, dst_ip=dst_ip
        )
        ip = build_ipv4(src_ip, dst_ip, IP_PROTO_TCP, tcp)
        return parse_ipv4(ip)
    
    def test_in_order_delivery(self):
        reassembler = TCPStreamReassembler()
        
        ip1 = self._build_ip_tcp(1000, TCP_FLAG_SYN, b"")
        tcp1 = parse_tcp(ip1.payload, self.src_ip, self.dst_ip)
        _, _, _, _, data1, data2 = reassembler.process(ip1, tcp1)
        
        ip2 = self._build_ip_tcp(1001, TCP_FLAG_ACK, b"Hello")
        tcp2 = parse_tcp(ip2.payload, self.src_ip, self.dst_ip)
        _, _, _, _, data1, data2 = reassembler.process(ip2, tcp2)
        
        self.assertEqual(data1, b"Hello")
    
    def test_out_of_order(self):
        reassembler = TCPStreamReassembler()
        
        ip1 = self._build_ip_tcp(1000, TCP_FLAG_SYN, b"")
        tcp1 = parse_tcp(ip1.payload, self.src_ip, self.dst_ip)
        reassembler.process(ip1, tcp1)
        
        ip2 = self._build_ip_tcp(1007, TCP_FLAG_ACK, b"World")
        tcp2 = parse_tcp(ip2.payload, self.src_ip, self.dst_ip)
        _, _, _, _, data1, _ = reassembler.process(ip2, tcp2)
        self.assertEqual(data1, b"")
        
        ip3 = self._build_ip_tcp(1001, TCP_FLAG_ACK, b"Hello ")
        tcp3 = parse_tcp(ip3.payload, self.src_ip, self.dst_ip)
        _, _, _, _, data1, _ = reassembler.process(ip3, tcp3)
        
        self.assertEqual(data1, b"Hello World")
    
    def test_duplicate_data(self):
        reassembler = TCPStreamReassembler()
        
        ip1 = self._build_ip_tcp(1000, TCP_FLAG_SYN, b"")
        tcp1 = parse_tcp(ip1.payload, self.src_ip, self.dst_ip)
        reassembler.process(ip1, tcp1)
        
        ip2 = self._build_ip_tcp(1001, TCP_FLAG_ACK, b"Hello")
        tcp2 = parse_tcp(ip2.payload, self.src_ip, self.dst_ip)
        reassembler.process(ip2, tcp2)
        
        ip3 = self._build_ip_tcp(1001, TCP_FLAG_ACK, b"Hello")
        tcp3 = parse_tcp(ip3.payload, self.src_ip, self.dst_ip)
        _, _, _, _, data1, _ = reassembler.process(ip3, tcp3)
        
        self.assertEqual(data1, b"")
    
    def test_five_tuple_key(self):
        key1 = get_five_tuple_key("1.1.1.1", 1000, "2.2.2.2", 2000, 6)
        key2 = get_five_tuple_key("2.2.2.2", 2000, "1.1.1.1", 1000, 6)
        self.assertEqual(key1, key2)
    
    def test_connection_state(self):
        reassembler = TCPStreamReassembler()
        
        ip1 = self._build_ip_tcp(1000, TCP_FLAG_SYN, b"")
        tcp1 = parse_tcp(ip1.payload, self.src_ip, self.dst_ip)
        reassembler.process(ip1, tcp1)
        
        conns = reassembler.get_all_connections()
        self.assertEqual(len(conns), 1)


class TestAppProtocolIdentification(unittest.TestCase):
    """应用层协议识别测试"""
    
    def test_http_request(self):
        data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        proto = identify_protocol(data, 12345, 80, is_tcp=True)
        self.assertEqual(proto, AppProtocol.HTTP)
    
    def test_http_response(self):
        data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"
        proto = identify_protocol(data, 80, 12345, is_tcp=True)
        self.assertEqual(proto, AppProtocol.HTTP)
    
    def test_https_port(self):
        proto = identify_protocol(b"", 12345, 443, is_tcp=True)
        self.assertEqual(proto, AppProtocol.HTTPS)
    
    def test_tls_handshake(self):
        data = b"\x16\x03\x01\x00\x20\x01\x00\x00\x1c\x03\x03" + b"\x00" * 20
        identifier = AppProtocolIdentifier()
        result = identifier.identify(data, 12345, 443, is_tcp=True)
        self.assertEqual(result.protocol, AppProtocol.TLS)
    
    def test_ssh(self):
        data = b"SSH-2.0-OpenSSH_8.0\r\n"
        proto = identify_protocol(data, 22, 12345, is_tcp=True)
        self.assertEqual(proto, AppProtocol.SSH)
    
    def test_dns_port(self):
        proto = identify_protocol(b"", 53, 12345, is_tcp=False)
        self.assertEqual(proto, AppProtocol.DNS)
    
    def test_confidence_level(self):
        identifier = AppProtocolIdentifier()
        data = b"GET / HTTP/1.1\r\nHost: x.com\r\n\r\n"
        result = identifier.identify(data, 12345, 80, is_tcp=True)
        self.assertGreater(result.confidence, 0.7)
    
    def test_unknown_protocol(self):
        data = b"\x00\x01\x02\x03\x04"
        proto = identify_protocol(data, 9999, 8888, is_tcp=True)
        self.assertEqual(proto, AppProtocol.UNKNOWN)


class TestFilter(unittest.TestCase):
    """过滤模块测试"""
    
    def setUp(self):
        self.ctx = FilterContext()
    
    def _make_http_ctx(self):
        ctx = FilterContext()
        ctx.ip = parse_ipv4(build_ipv4("192.168.1.1", "10.0.0.1", IP_PROTO_TCP,
            build_tcp(12345, 80, seq=1, flags=TCP_FLAG_ACK,
                     payload=b"GET / HTTP/1.1\r\n\r\n",
                     src_ip="192.168.1.1", dst_ip="10.0.0.1"),
        ))
        ctx.tcp = parse_tcp(ctx.ip.payload, "192.168.1.1", "10.0.0.1")
        ctx.app_protocol = "http"
        return ctx
    
    def test_filter_tcp(self):
        f = PacketFilter("tcp")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_filter_port(self):
        f = PacketFilter("tcp port 80")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_filter_ip_src(self):
        f = PacketFilter("ip src 192.168.1.1")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_filter_and(self):
        f = PacketFilter("tcp and ip src 192.168.1.1")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_filter_or(self):
        f = PacketFilter("tcp port 80 or tcp port 443")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_filter_not(self):
        f = PacketFilter("not udp")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_filter_syn(self):
        f = PacketFilter("tcp flags syn")
        ctx = self._make_http_ctx()
        self.assertFalse(f.match(ctx))
    
    def test_filter_ttp_comparison(self):
        f = PacketFilter("ip ttl > 10")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_filter_invalid_expression(self):
        f = PacketFilter("")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_filter_no_match(self):
        f = PacketFilter("udp")
        ctx = self._make_http_ctx()
        self.assertFalse(f.match(ctx))
    
    def test_tcp_flags_syn_match(self):
        f = PacketFilter("tcp flags syn")
        ctx = FilterContext()
        ctx.ip = parse_ipv4(build_ipv4("192.168.1.1", "10.0.0.1", IP_PROTO_TCP,
            build_tcp(12345, 80, seq=1000, flags=TCP_FLAG_SYN,
                     src_ip="192.168.1.1", dst_ip="10.0.0.1"),
        ))
        ctx.tcp = parse_tcp(ctx.ip.payload, "192.168.1.1", "10.0.0.1")
        self.assertTrue(f.match(ctx))
    
    def test_tcp_flags_syn_no_match_ack(self):
        f = PacketFilter("tcp flags syn")
        ctx = self._make_http_ctx()
        self.assertFalse(f.match(ctx))
    
    def test_tcp_flags_ack_match(self):
        f = PacketFilter("tcp flags ack")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_tcp_flags_fin_no_match(self):
        f = PacketFilter("tcp flags fin")
        ctx = self._make_http_ctx()
        self.assertFalse(f.match(ctx))
    
    def test_tcp_src_port(self):
        f = PacketFilter("tcp src port 12345")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_tcp_src_port_no_match(self):
        f = PacketFilter("tcp src port 80")
        ctx = self._make_http_ctx()
        self.assertFalse(f.match(ctx))
    
    def test_tcp_dst_port(self):
        f = PacketFilter("tcp dst port 80")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_tcp_dst_port_no_match(self):
        f = PacketFilter("tcp dst port 12345")
        ctx = self._make_http_ctx()
        self.assertFalse(f.match(ctx))
    
    def test_udp_src_port(self):
        f = PacketFilter("udp src port 123")
        ctx = FilterContext()
        ctx.ip = parse_ipv4(build_ipv4("192.168.1.1", "10.0.0.1", IP_PROTO_UDP,
            build_udp(123, 456, b"test",
                     src_ip="192.168.1.1", dst_ip="10.0.0.1"),
        ))
        ctx.udp = parse_udp(ctx.ip.payload, "192.168.1.1", "10.0.0.1")
        self.assertTrue(f.match(ctx))
    
    def test_udp_dst_port(self):
        f = PacketFilter("udp dst port 161")
        ctx = FilterContext()
        ctx.ip = parse_ipv4(build_ipv4("192.168.1.1", "10.0.0.1", IP_PROTO_UDP,
            build_udp(12345, 161, b"test",
                     src_ip="192.168.1.1", dst_ip="10.0.0.1"),
        ))
        ctx.udp = parse_udp(ctx.ip.payload, "192.168.1.1", "10.0.0.1")
        self.assertTrue(f.match(ctx))
    
    def test_ip_host_match_src(self):
        f = PacketFilter("ip host 192.168.1.1")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_ip_host_match_dst(self):
        f = PacketFilter("ip host 10.0.0.1")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_ip_host_no_match(self):
        f = PacketFilter("ip host 172.16.0.1")
        ctx = self._make_http_ctx()
        self.assertFalse(f.match(ctx))
    
    def test_host_shortcut(self):
        f = PacketFilter("host 192.168.1.1")
        ctx = self._make_http_ctx()
        self.assertTrue(f.match(ctx))
    
    def test_ether_host(self):
        f = PacketFilter("ether host aa:bb:cc:dd:ee:ff")
        ctx = FilterContext()
        ctx.ethernet = parse_ethernet(build_ethernet(
            "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
            ETHERTYPE_IPV4, b"\x00" * 20
        ))
        self.assertTrue(f.match(ctx))
    
    def test_ether_src(self):
        f = PacketFilter("ether src aa:bb:cc:dd:ee:ff")
        ctx = FilterContext()
        ctx.ethernet = parse_ethernet(build_ethernet(
            "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
            ETHERTYPE_IPV4, b"\x00" * 20
        ))
        self.assertTrue(f.match(ctx))
    
    def test_ether_dst(self):
        f = PacketFilter("ether dst 11:22:33:44:55:66")
        ctx = FilterContext()
        ctx.ethernet = parse_ethernet(build_ethernet(
            "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
            ETHERTYPE_IPV4, b"\x00" * 20
        ))
        self.assertTrue(f.match(ctx))


class TestStatistics(unittest.TestCase):
    """统计模块测试"""
    
    def _make_ctx(self):
        ctx = FilterContext()
        ctx.ethernet = parse_ethernet(build_ethernet(
            "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66",
            ETHERTYPE_IPV4,
            build_ipv4("192.168.1.1", "10.0.0.1", IP_PROTO_TCP,
                build_tcp(12345, 80, payload=b"test",
                         src_ip="192.168.1.1", dst_ip="10.0.0.1"))
        ))
        ctx.ip = parse_ipv4(ctx.ethernet.payload)
        ctx.tcp = parse_tcp(ctx.ip.payload, "192.168.1.1", "10.0.0.1")
        ctx.app_protocol = "http"
        return ctx
    
    def test_global_stats(self):
        stats = StatisticsCollector()
        ctx = self._make_ctx()
        stats.record_packet(ctx)
        
        summary = stats.get_summary()
        self.assertEqual(summary["total_packets"], 1)
        self.assertGreater(summary["total_bytes"], 0)
    
    def test_protocol_stats(self):
        stats = StatisticsCollector()
        ctx = self._make_ctx()
        stats.record_packet(ctx)
        
        ip_stats = stats.get_ip_proto_stats()
        self.assertIn(IP_PROTO_TCP, ip_stats)
    
    def test_connection_stats(self):
        stats = StatisticsCollector()
        ctx = self._make_ctx()
        stats.record_packet(ctx)
        
        conn_stats = stats.get_connection_stats()
        self.assertGreater(len(conn_stats), 0)
    
    def test_top_connections(self):
        stats = StatisticsCollector()
        ctx = self._make_ctx()
        stats.record_packet(ctx)
        
        top = stats.get_top_connections(10)
        self.assertGreater(len(top), 0)
    
    def test_top_hosts(self):
        stats = StatisticsCollector()
        ctx = self._make_ctx()
        stats.record_packet(ctx)
        
        hosts = stats.get_top_hosts(10)
        self.assertGreater(len(hosts), 0)
    
    def test_reset(self):
        stats = StatisticsCollector()
        ctx = self._make_ctx()
        stats.record_packet(ctx)
        stats.reset()
        
        summary = stats.get_summary()
        self.assertEqual(summary["total_packets"], 0)


class TestNetworkAnalyzer(unittest.TestCase):
    """主分析器集成测试"""
    
    def test_analyze_full_frame(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        
        frame = _build_full_frame(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            "192.168.1.1",
            "10.0.0.1",
            12345,
            80,
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            tcp_flags=TCP_FLAG_ACK | TCP_FLAG_PSH,
        )
        
        result = analyzer.analyze(frame)
        
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.ethernet)
        self.assertIsNotNone(result.ip)
        self.assertIsNotNone(result.tcp)
        self.assertGreater(result.packet_number, 0)
    
    def test_filtered_packet(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        analyzer.set_filter("udp")
        
        frame = _build_full_frame(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            "192.168.1.1",
            "10.0.0.1",
            12345,
            80,
            b"test",
            is_tcp=True,
        )
        
        result = analyzer.analyze(frame)
        self.assertIsNone(result)
    
    def test_statistics(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        
        for i in range(10):
            frame = _build_full_frame(
                "aa:bb:cc:dd:ee:ff",
                "11:22:33:44:55:66",
                f"192.168.1.{i+1}",
                "10.0.0.1",
                10000 + i,
                80,
                b"test",
            )
            analyzer.analyze(frame)
        
        stats = analyzer.get_statistics()
        self.assertEqual(stats["total_packets"], 10)
    
    def test_tcp_stream_reassembly(self):
        analyzer = NetworkAnalyzer(enable_reassembly=True)
        
        frame1 = _build_full_frame(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            b"",
            tcp_flags=TCP_FLAG_SYN,
        )
        analyzer.analyze(frame1)
        
        frame2 = _build_full_frame(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            b"Hello World",
            tcp_flags=TCP_FLAG_ACK,
        )
        
        pkt = parse_ethernet(frame2)
        ip = parse_ipv4(pkt.payload)
        tcp = parse_tcp(ip.payload, ip.header.src_ip, ip.header.dst_ip)
        tcp.seq = 1
        
        analyzer.analyze(frame2)
        
        streams = analyzer.get_all_streams()
        self.assertGreater(len(streams), 0)
    
    def test_packet_count(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        
        for i in range(5):
            frame = _build_full_frame(
                "aa:bb:cc:dd:ee:ff",
                "11:22:33:44:55:66",
                "1.1.1.1", "2.2.2.2",
                1000 + i, 2000,
                b"test",
            )
            analyzer.analyze(frame)
        
        self.assertEqual(analyzer.get_packet_count(), 5)
    
    def test_truncated_packet(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        
        result = analyzer.analyze(b"\x00\x01\x02")
        self.assertIsNotNone(result)
        self.assertTrue(result.ethernet.is_truncated)
    
    def test_udp_ntp_port_no_crash(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        
        frame = _build_full_frame(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            "192.168.1.1",
            "10.0.0.1",
            123,
            123,
            b"\x1b" + b"\x00" * 47,
            is_tcp=False,
        )
        
        result = analyzer.analyze(frame)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.udp)
        self.assertEqual(result.udp.src_port, 123)
        self.assertEqual(result.udp.dst_port, 123)
        self.assertIsNotNone(result.app_protocol)
    
    def test_udp_snmp_port_no_crash(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        
        frame = _build_full_frame(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            "192.168.1.1",
            "10.0.0.1",
            161,
            162,
            b"\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x01\x02\x03\x04"
            b"\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08+\x06\x01\x02\x01"
            b"\x01\x01\x00\x05\x00",
            is_tcp=False,
        )
        
        result = analyzer.analyze(frame)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.udp)
        self.assertEqual(result.udp.src_port, 161)
        self.assertEqual(result.udp.dst_port, 162)
        self.assertIsNotNone(result.app_protocol)
    
    def test_udp_ntp_with_filter(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        analyzer.set_filter("udp port 123")
        
        frame = _build_full_frame(
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
            "192.168.1.1",
            "10.0.0.1",
            123,
            123,
            b"\x1b" + b"\x00" * 47,
            is_tcp=False,
        )
        
        result = analyzer.analyze(frame)
        self.assertIsNotNone(result)
    
    def test_udp_ntp_stats(self):
        analyzer = NetworkAnalyzer(enable_reassembly=False)
        
        for i in range(5):
            frame = _build_full_frame(
                "aa:bb:cc:dd:ee:ff",
                "11:22:33:44:55:66",
                f"192.168.1.{i+1}",
                "10.0.0.1",
                123,
                123,
                b"\x1b" + b"\x00" * 47,
                is_tcp=False,
            )
            analyzer.analyze(frame)
        
        stats = analyzer.get_statistics()
        self.assertEqual(stats["total_packets"], 5)
        self.assertGreater(stats["app_proto_count"], 0)
        
        detailed = analyzer.get_detailed_stats()
        self.assertIn("app_protocols", detailed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
