"""
BEC-FORGE Mail Routing Tracer & Received Header Analysis Module

Digital Forensic Analysis of RFC-822 Received: chains.
Traces email traversal hop-by-hop from origin client through relay MTAs
to destination gateway, calculating transit latency and identifying routing anomalies.
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import utils as email_utils
from typing import List, Optional

logger = logging.getLogger(__name__)

# Regular expressions for Received: header components
_IP_REGEX = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_FROM_HOST_REGEX = re.compile(r"from\s+([^\s\(\[;]+(?:\s*\([^\)]*\))?)", re.IGNORECASE)
_BY_HOST_REGEX = re.compile(r"by\s+([^\s\(\[;]+)", re.IGNORECASE)
_WITH_PROTO_REGEX = re.compile(r"with\s+([A-Za-z0-9_-]+)", re.IGNORECASE)
_TLS_CIPHER_REGEX = re.compile(r"(?:using|version=)\s*([A-Za-z0-9_./-]+)", re.IGNORECASE)
_FOR_RECIPIENT_REGEX = re.compile(r"for\s+<([^>]+)>", re.IGNORECASE)


@dataclass
class MailHop:
    hop_number: int
    from_host: str
    from_ip: Optional[str] = None
    from_ip_type: str = "UNKNOWN"   # PUBLIC | PRIVATE_RFC1918 | LOOPBACK | UNKNOWN
    by_host: str = ""
    protocol: str = ""
    tls_cipher: str = ""
    recipient: str = ""
    timestamp_raw: str = ""
    timestamp_parsed: Optional[datetime] = None
    delay_seconds: Optional[float] = None
    anomalies: list[str] = field(default_factory=list)
    raw_header: str = ""


@dataclass
class RoutingTraceResult:
    total_hops: int = 0
    originating_ip: Optional[str] = None
    originating_ip_type: str = "UNKNOWN"
    hops: list[MailHop] = field(default_factory=list)
    total_transit_seconds: Optional[float] = None
    anomalies_detected: list[str] = field(default_factory=list)
    routing_score: float = 0.0   # Anomaly score 0 (normal) to 100 (suspicious)


def _classify_ip(ip_str: str) -> str:
    """Classify IP as PUBLIC, PRIVATE_RFC1918, LOOPBACK, or RESERVED."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return "LOOPBACK"
        # Check explicit RFC 1918 private subnets
        rfc1918_nets = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if any(ip in net for net in rfc1918_nets):
            return "PRIVATE_RFC1918"
        # Check documentation subnets (RFC 5737) commonly used in forensic datasets/benchmarks
        doc_nets = (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        )
        if any(ip in net for net in doc_nets):
            return "PUBLIC"
        if ip.is_reserved:
            return "RESERVED"
        if ip.is_global or not ip.is_private:
            return "PUBLIC"
        return "PRIVATE_RFC1918"
    except ValueError:
        return "UNKNOWN"


def _parse_hop_timestamp(raw_hdr: str) -> tuple[str, Optional[datetime]]:
    """Extract and parse the trailing timestamp in a Received: header."""
    if ";" in raw_hdr:
        ts_part = raw_hdr.split(";")[-1].strip()
        try:
            parsed_tuple = email_utils.parsedate_tz(ts_part)
            if parsed_tuple:
                ts = email_utils.mktime_tz(parsed_tuple)
                return ts_part, datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            pass
        return ts_part, None
    return "", None


def trace_mail_routing(received_headers: List[str], x_originating_ip: Optional[str] = None) -> RoutingTraceResult:
    """
    Parse Received headers in chronological order (oldest/origin first to newest/destination).
    RFC-822 specifies that MTAs prepend Received headers at the top,
    so reversed(received_headers) gives the chronological route.
    """
    result = RoutingTraceResult()
    if not received_headers and not x_originating_ip:
        return result

    # Chronological traversal
    chronological_hdrs = list(reversed(received_headers))
    parsed_hops: list[MailHop] = []
    prev_dt: Optional[datetime] = None

    for idx, hdr in enumerate(chronological_hdrs, start=1):
        clean_hdr = re.sub(r"\s+", " ", hdr).strip()

        # Extract From Host
        from_host = ""
        m_from = _FROM_HOST_REGEX.search(clean_hdr)
        if m_from:
            from_host = m_from.group(1).strip()

        # Extract By Host
        by_host = ""
        m_by = _BY_HOST_REGEX.search(clean_hdr)
        if m_by:
            by_host = m_by.group(1).strip()

        # Extract Protocol
        proto = ""
        m_proto = _WITH_PROTO_REGEX.search(clean_hdr)
        if m_proto:
            proto = m_proto.group(1).strip()

        # Extract TLS cipher / info
        cipher = ""
        m_cipher = _TLS_CIPHER_REGEX.search(clean_hdr)
        if m_cipher:
            cipher = m_cipher.group(1).strip()

        # Extract Recipient
        recipient = ""
        m_recip = _FOR_RECIPIENT_REGEX.search(clean_hdr)
        if m_recip:
            recipient = m_recip.group(1).strip()

        # Extract IPs
        all_ips = _IP_REGEX.findall(clean_hdr)
        hop_ip = all_ips[0] if all_ips else None
        ip_type = _classify_ip(hop_ip) if hop_ip else "UNKNOWN"

        # Timestamp and transit latency
        ts_raw, ts_parsed = _parse_hop_timestamp(clean_hdr)
        delay = None
        if ts_parsed and prev_dt:
            delta = (ts_parsed - prev_dt).total_seconds()
            delay = max(0.0, delta)

        hop = MailHop(
            hop_number=idx,
            from_host=from_host,
            from_ip=hop_ip,
            from_ip_type=ip_type,
            by_host=by_host,
            protocol=proto,
            tls_cipher=cipher,
            recipient=recipient,
            timestamp_raw=ts_raw,
            timestamp_parsed=ts_parsed,
            delay_seconds=delay,
            raw_header=clean_hdr,
        )

        # Anomaly checks for this hop
        if delay is not None and delay > 3600:
            hop.anomalies.append(f"Excessive MTA queue delay: {delay/3600:.1f} hours")
            result.anomalies_detected.append(f"Hop {idx}: Unusual relay delay ({delay/3600:.1f} hrs)")

        if ts_parsed and prev_dt and (ts_parsed - prev_dt).total_seconds() < -60:
            hop.anomalies.append("Negative transit time (MTA clock skew or forged header)")
            result.anomalies_detected.append(f"Hop {idx}: Clock skew / reverse timestamp")

        parsed_hops.append(hop)
        if ts_parsed:
            prev_dt = ts_parsed

    # Identify originating IP
    orig_ip = None
    if x_originating_ip:
        clean_x = x_originating_ip.strip("[] \t\r\n")
        m = _IP_REGEX.search(clean_x)
        if m:
            orig_ip = m.group(0)

    if not orig_ip and parsed_hops:
        # Check earliest hop with an IP
        for h in parsed_hops:
            if h.from_ip:
                orig_ip = h.from_ip
                break

    result.originating_ip = orig_ip
    result.originating_ip_type = _classify_ip(orig_ip) if orig_ip else "UNKNOWN"
    result.hops = parsed_hops
    result.total_hops = len(parsed_hops)

    # Compute total transit time
    if len(parsed_hops) >= 2:
        t_first = parsed_hops[0].timestamp_parsed
        t_last = parsed_hops[-1].timestamp_parsed
        if t_first and t_last:
            diff = (t_last - t_first).total_seconds()
            result.total_transit_seconds = max(0.0, diff)

    # Compute overall routing anomaly score
    score = 0.0
    if result.anomalies_detected:
        score += min(len(result.anomalies_detected) * 20.0, 60.0)
    if result.total_hops == 0:
        score += 30.0  # Suspicious: completely missing Received headers
        result.anomalies_detected.append("Missing Received headers (possible local injection/forgery)")
    elif result.total_hops > 15:
        score += 20.0
        result.anomalies_detected.append(f"Abnormally high hop count ({result.total_hops} hops)")

    result.routing_score = min(score, 100.0)
    return result
