"""
数据包过滤
===========
支持按各层协议字段筛选数据包，类似 tcpdump 过滤表达式语法。

支持的过滤字段:

链路层 (Ethernet):
- ether src <mac>       源MAC地址
- ether dst <mac>       目的MAC地址
- ether host <mac>      MAC地址(源或目的)
- ether type <type>     以太类型

网络层 (IP):
- ip                    是否是IPv4
- ip src <ip>           源IP地址
- ip dst <ip>           目的IP地址
- ip host <ip>          IP地址(源或目的)
- ip proto <protocol>   协议号
- ip ttl <value>        TTL值
- ip id <id>            标识字段

传输层 (TCP/UDP):
- tcp                   是否是TCP
- udp                   是否是UDP
- tcp src port <port>   TCP源端口
- tcp dst port <port>   TCP目的端口
- tcp port <port>       TCP端口(源或目的)
- udp src port <port>   UDP源端口
- udp dst port <port>   UDP目的端口
- udp port <port>       UDP端口(源或目的)
- tcp flags <flags>     TCP标志位 (syn, ack, fin, rst, psh, urg)

应用层:
- port <port>           端口(源或目的, TCP或UDP)
- http                  HTTP协议
- https                 HTTPS协议

比较操作符:
- =, ==, !=             等于、不等于
- <, <=, >, >=          小于、小于等于、大于、大于等于

逻辑操作符:
- and, &&               逻辑与
- or, ||                逻辑或
- not, !                逻辑非

示例:
- "tcp port 80"
- "ip src 192.168.1.1 and tcp dst port 443"
- "tcp flags syn"
- "not arp and port 53"
- "ip ttl > 64"
"""

import re
import ipaddress
from dataclasses import dataclass, field
from typing import Optional, List, Callable, Any, Dict
from enum import Enum


class FilterOperator(Enum):
    EQ = "=="
    NEQ = "!="
    LT = "<"
    GT = ">"
    LE = "<="
    GE = ">="


class FilterTokenType(Enum):
    IDENTIFIER = "identifier"
    NUMBER = "number"
    IP = "ip"
    MAC = "mac"
    STRING = "string"
    OP_EQ = "=="
    OP_NEQ = "!="
    OP_LT = "<"
    OP_GT = ">"
    OP_LE = "<="
    OP_GE = ">="
    KW_AND = "and"
    KW_OR = "or"
    KW_NOT = "not"
    LPAREN = "("
    RPAREN = ")"


@dataclass
class FilterToken:
    type: FilterTokenType
    value: Any = None
    position: int = 0


@dataclass
class FilterContext:
    """过滤上下文 - 包含各层解析结果"""
    ethernet: Optional[Any] = None
    ip: Optional[Any] = None
    tcp: Optional[Any] = None
    udp: Optional[Any] = None
    app_protocol: Optional[str] = None


class FilterExpression:
    """过滤表达式基类"""
    
    def evaluate(self, ctx: FilterContext) -> bool:
        raise NotImplementedError


@dataclass
class AndExpression(FilterExpression):
    left: FilterExpression
    right: FilterExpression
    
    def evaluate(self, ctx: FilterContext) -> bool:
        return self.left.evaluate(ctx) and self.right.evaluate(ctx)


@dataclass
class OrExpression(FilterExpression):
    left: FilterExpression
    right: FilterExpression
    
    def evaluate(self, ctx: FilterContext) -> bool:
        return self.left.evaluate(ctx) or self.right.evaluate(ctx)


@dataclass
class NotExpression(FilterExpression):
    expr: FilterExpression
    
    def evaluate(self, ctx: FilterContext) -> bool:
        return not self.expr.evaluate(ctx)


@dataclass
class SimpleFilter(FilterExpression):
    field: str
    operator: FilterOperator
    value: Any
    
    def evaluate(self, ctx: FilterContext) -> bool:
        actual = self._get_field_value(ctx)
        if actual is None:
            return False
        
        try:
            return self._compare(actual, self.value)
        except (TypeError, ValueError):
            return False
    
    def _get_field_value(self, ctx: FilterContext) -> Any:
        field = self.field.lower()
        
        if field == "ether.src" and ctx.ethernet:
            return ctx.ethernet.src_mac
        if field == "ether.dst" and ctx.ethernet:
            return ctx.ethernet.dst_mac
        if field == "ether.host" and ctx.ethernet:
            return [ctx.ethernet.src_mac, ctx.ethernet.dst_mac]
        if field == "ether.type" and ctx.ethernet:
            return ctx.ethernet.ethertype
        
        if field == "ip" and ctx.ip:
            return True
        if field == "ip.src" and ctx.ip:
            return ctx.ip.header.src_ip
        if field == "ip.dst" and ctx.ip:
            return ctx.ip.header.dst_ip
        if field == "ip.host" and ctx.ip:
            return [ctx.ip.header.src_ip, ctx.ip.header.dst_ip]
        if field == "ip.proto" and ctx.ip:
            return ctx.ip.header.protocol
        if field == "ip.ttl" and ctx.ip:
            return ctx.ip.header.ttl
        if field == "ip.id" and ctx.ip:
            return ctx.ip.header.identification
        if field == "ip.len" and ctx.ip:
            return ctx.ip.header.total_length
        
        if field == "tcp" and ctx.tcp:
            return True
        if field == "tcp.srcport" and ctx.tcp:
            return ctx.tcp.src_port
        if field == "tcp.dstport" and ctx.tcp:
            return ctx.tcp.dst_port
        if field == "tcp.seq" and ctx.tcp:
            return ctx.tcp.seq
        if field == "tcp.ack" and ctx.tcp:
            return ctx.tcp.ack
        if field == "tcp.window" and ctx.tcp:
            return ctx.tcp.window_size
        
        if field == "udp" and ctx.udp:
            return True
        if field == "udp.srcport" and ctx.udp:
            return ctx.udp.src_port
        if field == "udp.dstport" and ctx.udp:
            return ctx.udp.dst_port
        if field == "udp.length" and ctx.udp:
            return ctx.udp.length
        
        if field in ("tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin",
                     "tcp.flags.rst", "tcp.flags.psh", "tcp.flags.urg"):
            if not ctx.tcp:
                return None
            flag_name = field.split(".")[-1].upper()
            flag_map = {
                "SYN": ctx.tcp.syn,
                "ACK": ctx.tcp.ack_flag,
                "FIN": ctx.tcp.fin,
                "RST": ctx.tcp.rst,
                "PSH": ctx.tcp.psh,
                "URG": ctx.tcp.urg,
            }
            return flag_map.get(flag_name, False)
        
        if field == "http":
            return ctx.app_protocol == "http"
        if field == "https":
            return ctx.app_protocol == "https"
        if field == "dns":
            return ctx.app_protocol == "dns"
        if field == "ssh":
            return ctx.app_protocol == "ssh"
        if field == "ftp":
            return ctx.app_protocol == "ftp"
        
        if field == "port":
            ports = []
            if ctx.tcp:
                ports.extend([ctx.tcp.src_port, ctx.tcp.dst_port])
            if ctx.udp:
                ports.extend([ctx.udp.src_port, ctx.udp.dst_port])
            return ports if ports else None
        
        if field == "tcp.port":
            if not ctx.tcp:
                return None
            return [ctx.tcp.src_port, ctx.tcp.dst_port]
        
        if field == "udp.port":
            if not ctx.udp:
                return None
            return [ctx.udp.src_port, ctx.udp.dst_port]
        
        if field == "srcport":
            if ctx.tcp:
                return ctx.tcp.src_port
            if ctx.udp:
                return ctx.udp.src_port
            return None
        if field == "dstport":
            if ctx.tcp:
                return ctx.tcp.dst_port
            if ctx.udp:
                return ctx.udp.dst_port
            return None
        
        if field == "srcip":
            return ctx.ip.header.src_ip if ctx.ip else None
        if field == "dstip":
            return ctx.ip.header.dst_ip if ctx.ip else None
        
        return None
    
    def _compare(self, actual: Any, expected: Any) -> bool:
        if isinstance(actual, list):
            if self.operator == FilterOperator.EQ:
                if isinstance(expected, str):
                    return any(
                        str(a).lower() == expected.lower()
                        for a in actual
                    )
                return expected in actual
            if self.operator == FilterOperator.NEQ:
                if isinstance(expected, str):
                    return all(
                        str(a).lower() != expected.lower()
                        for a in actual
                    )
                return expected not in actual
            try:
                actual_vals = [float(a) if not isinstance(a, bool) else int(a) for a in actual]
                expected_val = float(expected) if not isinstance(expected, bool) else int(expected)
            except (ValueError, TypeError):
                return False
            if self.operator == FilterOperator.LT:
                return max(actual_vals) < expected_val
            if self.operator == FilterOperator.GT:
                return min(actual_vals) > expected_val
            if self.operator == FilterOperator.LE:
                return max(actual_vals) <= expected_val
            if self.operator == FilterOperator.GE:
                return min(actual_vals) >= expected_val
            return False
        
        if self.operator == FilterOperator.EQ:
            if isinstance(actual, str) and isinstance(expected, str):
                return actual.lower() == expected.lower()
            return actual == expected
        if self.operator == FilterOperator.NEQ:
            if isinstance(actual, str) and isinstance(expected, str):
                return actual.lower() != expected.lower()
            return actual != expected
        
        try:
            actual_val = float(actual) if not isinstance(actual, bool) else int(actual)
            expected_val = float(expected) if not isinstance(expected, bool) else int(expected)
        except (ValueError, TypeError):
            return False
        
        if self.operator == FilterOperator.LT:
            return actual_val < expected_val
        if self.operator == FilterOperator.GT:
            return actual_val > expected_val
        if self.operator == FilterOperator.LE:
            return actual_val <= expected_val
        if self.operator == FilterOperator.GE:
            return actual_val >= expected_val
        
        return False


@dataclass
class BooleanFilter(FilterExpression):
    field: str
    
    def evaluate(self, ctx: FilterContext) -> bool:
        field = self.field.lower()
        
        if field == "ip":
            return ctx.ip is not None
        if field == "tcp":
            return ctx.tcp is not None
        if field == "udp":
            return ctx.udp is not None
        if field == "ether":
            return ctx.ethernet is not None
        if field == "arp":
            return ctx.ethernet is not None and ctx.ethernet.ethertype == 0x0806
        if field == "http":
            return ctx.app_protocol == "http"
        if field == "https":
            return ctx.app_protocol == "https"
        if field == "dns":
            return ctx.app_protocol == "dns"
        if field == "ssh":
            return ctx.app_protocol == "ssh"
        if field == "ftp":
            return ctx.app_protocol == "ftp"
        if field == "smtp":
            return ctx.app_protocol == "smtp"
        
        if field.startswith("tcp.flags.") and ctx.tcp:
            flag_name = field.split(".")[-1].upper()
            flag_map = {
                "SYN": ctx.tcp.syn,
                "ACK": ctx.tcp.ack_flag,
                "FIN": ctx.tcp.fin,
                "RST": ctx.tcp.rst,
                "PSH": ctx.tcp.psh,
                "URG": ctx.tcp.urg,
            }
            return flag_map.get(flag_name, False)
        
        if field.startswith("ip.flags.") and ctx.ip:
            flag_name = field.split(".")[-1].lower()
            if flag_name == "df":
                return ctx.ip.header.df_flag
            if flag_name == "mf":
                return ctx.ip.header.mf_flag
            return False
        
        if field == "tcp.flags" and ctx.tcp:
            return True
        if field == "ip.flags" and ctx.ip:
            return True
        
        return False


class FilterParser:
    """
    过滤表达式解析器
    
    将过滤表达式字符串解析为表达式树。
    
    语法 (简化的BNF):
        expression  := or_expr
        or_expr     := and_expr ( "or" and_expr )*
        and_expr    := not_expr ( "and" not_expr )*
        not_expr    := "not" not_expr | primary
        primary     := identifier [ ( "=" | "!=" | "<" | ">" | "<=" | ">=" ) value ]
                     | "(" expression ")"
    """
    
    def __init__(self, expr_str: str):
        self.expr_str = expr_str
        self.tokens: List[FilterToken] = []
        self.pos: int = 0
        self._tokenize()
    
    def _tokenize(self):
        """词法分析 - 将表达式拆分为token"""
        i = 0
        s = self.expr_str
        
        while i < len(s):
            if s[i].isspace():
                i += 1
                continue
            
            if s[i] == "(":
                self.tokens.append(FilterToken(type=FilterTokenType.LPAREN, position=i))
                i += 1
                continue
            
            if s[i] == ")":
                self.tokens.append(FilterToken(type=FilterTokenType.RPAREN, position=i))
                i += 1
                continue
            
            if s.startswith("==", i):
                self.tokens.append(FilterToken(type=FilterTokenType.OP_EQ, position=i))
                i += 2
                continue
            if s.startswith("!=", i):
                self.tokens.append(FilterToken(type=FilterTokenType.OP_NEQ, position=i))
                i += 2
                continue
            if s.startswith("<=", i):
                self.tokens.append(FilterToken(type=FilterTokenType.OP_LE, position=i))
                i += 2
                continue
            if s.startswith(">=", i):
                self.tokens.append(FilterToken(type=FilterTokenType.OP_GE, position=i))
                i += 2
                continue
            if s[i] == "<":
                self.tokens.append(FilterToken(type=FilterTokenType.OP_LT, position=i))
                i += 1
                continue
            if s[i] == ">":
                self.tokens.append(FilterToken(type=FilterTokenType.OP_GT, position=i))
                i += 1
                continue
            
            if s[i] == '"':
                j = i + 1
                while j < len(s) and s[j] != '"':
                    if s[j] == "\\":
                        j += 1
                    j += 1
                val = s[i+1:j] if j < len(s) else s[i+1:]
                self.tokens.append(FilterToken(type=FilterTokenType.STRING, value=val, position=i))
                i = j + 1 if j < len(s) else len(s)
                continue
            
            if s[i].isdigit():
                j = i
                while j < len(s) and (s[j].isdigit() or s[j] in ".:"):
                    j += 1
                num_str = s[i:j]
                
                if re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", num_str):
                    self.tokens.append(FilterToken(type=FilterTokenType.MAC, value=num_str.lower(), position=i))
                    i = j
                    continue
                
                if num_str.count(".") == 3 and ":" not in num_str:
                    try:
                        ipaddress.IPv4Address(num_str)
                        self.tokens.append(FilterToken(type=FilterTokenType.IP, value=num_str, position=i))
                        i = j
                        continue
                    except ValueError:
                        pass
                
                if ":" not in num_str:
                    try:
                        val = int(num_str) if "." not in num_str else float(num_str)
                        self.tokens.append(FilterToken(type=FilterTokenType.NUMBER, value=val, position=i))
                    except ValueError:
                        self.tokens.append(FilterToken(type=FilterTokenType.IDENTIFIER, value=num_str, position=i))
                else:
                    self.tokens.append(FilterToken(type=FilterTokenType.IDENTIFIER, value=num_str, position=i))
                i = j
                continue
            
            if s[i].isalpha() or s[i] == "_":
                j = i
                while j < len(s) and (s[j].isalnum() or s[j] in "._-:"):
                    j += 1
                ident = s[i:j]
                
                if re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", ident):
                    self.tokens.append(FilterToken(type=FilterTokenType.MAC, value=ident.lower(), position=i))
                elif ident.lower() == "and":
                    self.tokens.append(FilterToken(type=FilterTokenType.KW_AND, position=i))
                elif ident.lower() == "or":
                    self.tokens.append(FilterToken(type=FilterTokenType.KW_OR, position=i))
                elif ident.lower() == "not":
                    self.tokens.append(FilterToken(type=FilterTokenType.KW_NOT, position=i))
                else:
                    self.tokens.append(FilterToken(type=FilterTokenType.IDENTIFIER, value=ident, position=i))
                i = j
                continue
            
            i += 1
    
    def parse(self) -> FilterExpression:
        """解析表达式"""
        if not self.tokens:
            return BooleanFilter("")
        
        self.pos = 0
        expr = self._parse_or()
        
        if self.pos < len(self.tokens):
            raise ValueError(f"Unexpected token at position {self.tokens[self.pos].position}")
        
        return expr
    
    def _parse_or(self) -> FilterExpression:
        left = self._parse_and()
        
        while self.pos < len(self.tokens) and self.tokens[self.pos].type == FilterTokenType.KW_OR:
            self.pos += 1
            right = self._parse_and()
            left = OrExpression(left=left, right=right)
        
        return left
    
    def _parse_and(self) -> FilterExpression:
        left = self._parse_not()
        
        while self.pos < len(self.tokens) and self.tokens[self.pos].type == FilterTokenType.KW_AND:
            self.pos += 1
            right = self._parse_not()
            left = AndExpression(left=left, right=right)
        
        return left
    
    def _parse_not(self) -> FilterExpression:
        if self.pos < len(self.tokens) and self.tokens[self.pos].type == FilterTokenType.KW_NOT:
            self.pos += 1
            expr = self._parse_not()
            return NotExpression(expr=expr)
        
        return self._parse_primary()
    
    def _parse_primary(self) -> FilterExpression:
        if self.pos >= len(self.tokens):
            raise ValueError("Unexpected end of expression")
        
        token = self.tokens[self.pos]
        
        if token.type == FilterTokenType.LPAREN:
            self.pos += 1
            expr = self._parse_or()
            if self.pos >= len(self.tokens) or self.tokens[self.pos].type != FilterTokenType.RPAREN:
                raise ValueError("Missing closing parenthesis")
            self.pos += 1
            return expr
        
        if token.type == FilterTokenType.IDENTIFIER:
            field_name = token.value.lower()
            self.pos += 1
            
            field_name = self._combine_field_name(field_name)
            
            full_field = self._expand_field_name(field_name)
            
            if self._is_boolean_field(full_field):
                return BooleanFilter(full_field)
            
            if self.pos < len(self.tokens) and self.tokens[self.pos].type in (
                FilterTokenType.OP_EQ, FilterTokenType.OP_NEQ,
                FilterTokenType.OP_LT, FilterTokenType.OP_GT,
                FilterTokenType.OP_LE, FilterTokenType.OP_GE,
            ):
                op_token = self.tokens[self.pos]
                self.pos += 1
                
                if self.pos >= len(self.tokens):
                    raise ValueError("Expected value after operator")
                
                val_token = self.tokens[self.pos]
                self.pos += 1
                
                op_map = {
                    FilterTokenType.OP_EQ: FilterOperator.EQ,
                    FilterTokenType.OP_NEQ: FilterOperator.NEQ,
                    FilterTokenType.OP_LT: FilterOperator.LT,
                    FilterTokenType.OP_GT: FilterOperator.GT,
                    FilterTokenType.OP_LE: FilterOperator.LE,
                    FilterTokenType.OP_GE: FilterOperator.GE,
                }
                
                return SimpleFilter(
                    field=full_field,
                    operator=op_map[op_token.type],
                    value=val_token.value
                )
            
            if self.pos < len(self.tokens) and self.tokens[self.pos].type in (
                FilterTokenType.NUMBER,
                FilterTokenType.IP,
                FilterTokenType.MAC,
                FilterTokenType.STRING,
                FilterTokenType.IDENTIFIER,
            ):
                val_token = self.tokens[self.pos]
                self.pos += 1
                value = val_token.value
                
                if full_field.startswith("tcp.flags."):
                    flag_name = full_field.split(".")[-1].lower()
                    if isinstance(value, str) and value.lower() in ("1", "true", "set"):
                        value = True
                    elif isinstance(value, str) and value.lower() in ("0", "false", "not"):
                        value = False
                    else:
                        value = True
                
                return SimpleFilter(
                    field=full_field,
                    operator=FilterOperator.EQ,
                    value=value
                )
            
            return BooleanFilter(full_field)
        
        if token.type == FilterTokenType.NUMBER:
            self.pos += 1
            return SimpleFilter(field="port", operator=FilterOperator.EQ, value=token.value)
        
        raise ValueError(f"Unexpected token at position {token.position}: {token.type}")
    
    def _combine_field_name(self, first_part: str) -> str:
        """组合多个标识符为完整的字段名 (tcpdump风格)"""
        parts = [first_part]
        
        combine_keywords = {
            "src", "dst", "host", "port", "flags",
            "srcport", "dstport", "sport", "dport",
            "proto", "protocol", "ttl", "id", "len", "length",
            "syn", "ack", "fin", "rst", "psh", "urg",
            "type", "net",
        }
        
        while self.pos < len(self.tokens):
            next_token = self.tokens[self.pos]
            if next_token.type != FilterTokenType.IDENTIFIER:
                break
            
            val = next_token.value.lower()
            if val not in combine_keywords and not self._is_flag_name(val):
                break
            
            parts.append(val)
            self.pos += 1
        
        return self._normalize_field_parts(parts)
    
    def _is_flag_name(self, name: str) -> bool:
        """检查是否是TCP标志位名称"""
        return name.lower() in {"syn", "ack", "fin", "rst", "psh", "urg", "cwr", "ece"}
    
    def _normalize_field_parts(self, parts: List[str]) -> str:
        """将字段部分规范化为标准格式"""
        if len(parts) == 1:
            return parts[0]
        
        first = parts[0]
        
        if first in {"ether", "eth"}:
            if len(parts) == 2 and parts[1] in {"src", "dst", "host", "type"}:
                if parts[1] == "host":
                    return "ether.host"
                return f"ether.{parts[1]}"
            if len(parts) == 2 and self._is_flag_name(parts[1]):
                return f"ether.{parts[1]}"
            return ".".join(parts)
        
        if first == "ip":
            if len(parts) == 2 and parts[1] in {"src", "dst", "host", "proto", "protocol", "ttl", "id", "len", "length"}:
                if parts[1] == "host":
                    return "ip.host"
                if parts[1] in {"proto", "protocol"}:
                    return "ip.proto"
                if parts[1] in {"len", "length"}:
                    return "ip.len"
                return f"ip.{parts[1]}"
            if len(parts) >= 2 and parts[1] == "flags":
                if len(parts) == 3 and self._is_flag_name(parts[2]):
                    return f"ip.flags.{parts[2]}"
                return "ip"
            return ".".join(parts)
        
        if first in {"tcp", "udp"}:
            if len(parts) == 2 and parts[1] in {"srcport", "dstport", "sport", "dport", "port"}:
                if parts[1] == "port":
                    return f"{first}.port"
                if parts[1] in {"sport", "srcport"}:
                    return f"{first}.srcport"
                if parts[1] in {"dport", "dstport"}:
                    return f"{first}.dstport"
            if len(parts) == 3 and parts[1] in {"src", "dst"} and parts[2] == "port":
                if parts[1] == "src":
                    return f"{first}.srcport"
                if parts[1] == "dst":
                    return f"{first}.dstport"
            if len(parts) == 2 and parts[1] == "src":
                return f"{first}.srcport"
            if len(parts) == 2 and parts[1] == "dst":
                return f"{first}.dstport"
            if len(parts) >= 2 and parts[1] == "flags":
                if len(parts) == 3 and self._is_flag_name(parts[2]):
                    return f"{first}.flags.{parts[2]}"
                return f"{first}"
            if len(parts) == 2 and self._is_flag_name(parts[1]):
                return f"{first}.flags.{parts[1]}"
            if len(parts) == 2 and parts[1] in {"seq", "ack", "window"}:
                return f"{first}.{parts[1]}"
            return ".".join(parts)
        
        if first == "src":
            if len(parts) == 2 and parts[1] == "port":
                return "srcport"
            if len(parts) == 2 and parts[1] == "host":
                return "srcip"
            return "srcip"
        
        if first == "dst":
            if len(parts) == 2 and parts[1] == "port":
                return "dstport"
            if len(parts) == 2 and parts[1] == "host":
                return "dstip"
            return "dstip"
        
        if first == "host":
            return "ip.host"
        
        if first == "port":
            return "port"
        
        return ".".join(parts)
    
    def _is_boolean_field(self, field: str) -> bool:
        """检查是否是布尔类型的字段"""
        boolean_fields = {
            "ip", "tcp", "udp", "ether", "arp",
            "http", "https", "dns", "ssh", "ftp", "smtp",
            "icmp",
        }
        
        if field in boolean_fields:
            return True
        
        if field.startswith("tcp.flags.") or field.startswith("ip.flags."):
            return True
        
        return False
    
    def _expand_field_name(self, name: str) -> str:
        """展开简写的字段名"""
        name = name.lower()
        
        shortcuts = {
            "src": "srcip",
            "dst": "dstip",
            "host": "ip.host",
            "net": "ip.host",
            "port": "port",
            "srcport": "srcport",
            "dstport": "dstport",
            "sport": "srcport",
            "dport": "dstport",
            
            "ether.src": "ether.src",
            "ether.dst": "ether.dst",
            "ether.host": "ether.host",
            "ether.type": "ether.type",
            "eth.src": "ether.src",
            "eth.dst": "ether.dst",
            "eth.type": "ether.type",
            "eth.host": "ether.host",
            
            "ip.src": "ip.src",
            "ip.dst": "ip.dst",
            "ip.host": "ip.host",
            "ip.proto": "ip.proto",
            "ip.protocol": "ip.proto",
            "ip.ttl": "ip.ttl",
            "ip.id": "ip.id",
            "ip.len": "ip.len",
            "ip.length": "ip.len",
            
            "tcp.srcport": "tcp.srcport",
            "tcp.dstport": "tcp.dstport",
            "tcp.port": "tcp.port",
            "tcp.seq": "tcp.seq",
            "tcp.ack": "tcp.ack",
            "tcp.flags": "tcp",
            "tcp.flags.syn": "tcp.flags.syn",
            "tcp.flags.ack": "tcp.flags.ack",
            "tcp.flags.fin": "tcp.flags.fin",
            "tcp.flags.rst": "tcp.flags.rst",
            "tcp.flags.psh": "tcp.flags.psh",
            "tcp.flags.urg": "tcp.flags.urg",
            "tcp.window": "tcp.window",
            
            "udp.srcport": "udp.srcport",
            "udp.dstport": "udp.dstport",
            "udp.port": "udp.port",
            "udp.length": "udp.length",
        }
        
        if name in shortcuts:
            return shortcuts[name]
        
        return name


class PacketFilter:
    """
    数据包过滤器
    
    使用方法:
        f = PacketFilter("tcp port 80 and ip src 192.168.1.1")
        if f.match(context):
            # 数据包匹配
    """
    
    def __init__(self, expression: str = ""):
        """
        初始化过滤器
        
        Args:
            expression: 过滤表达式字符串
        
        Raises:
            ValueError: 如果表达式语法错误
        """
        self.expression = expression
        self._ast: Optional[FilterExpression] = None
        
        if expression:
            self._parse()
    
    def _parse(self):
        """解析过滤表达式"""
        parser = FilterParser(self.expression)
        self._ast = parser.parse()
    
    def match(self, ctx: FilterContext) -> bool:
        """
        检查数据包是否匹配过滤条件
        
        Args:
            ctx: 过滤上下文(包含各层解析结果)
        
        Returns:
            bool: 是否匹配
        """
        if not self.expression or self._ast is None:
            return True
        
        try:
            return self._ast.evaluate(ctx)
        except Exception:
            return False
    
    def set_expression(self, expression: str):
        """设置新的过滤表达式"""
        self.expression = expression
        self._parse()
    
    def validate(self, expression: str) -> bool:
        """验证表达式是否合法"""
        try:
            parser = FilterParser(expression)
            parser.parse()
            return True
        except Exception:
            return False


def create_filter(expression: str) -> PacketFilter:
    """便捷函数：创建过滤器"""
    return PacketFilter(expression)
