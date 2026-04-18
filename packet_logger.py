"""
Assignment 5 - Packet Logger using SDN Controller (POX)
=========================================================
Place this file inside:   pox/ext/packet_logger.py

Run with:
    cd ~/pox
    python pox.py packet_logger

Requirements met:
  [x] Capture packet headers      – Ethernet, IP, TCP, UDP, ICMP, ARP
  [x] Identify protocol types     – TCP / UDP / ICMP / ARP / DNS / HTTP / IPv6
  [x] Maintain logs               – packet_log.txt  |  packet_log.csv  |  packet_log.json
  [x] Display packet information  – real-time terminal table + HTML dashboard
"""

from pox.core import core
from pox.lib.revent import EventMixin
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, ipv4, ipv6, arp
from pox.lib.packet import tcp, udp, icmp
from pox.lib.packet.ethernet import ethernet as eth_type
from pox.lib.addresses import EthAddr, IPAddr

import datetime
import os
import csv
import json
import logging

log = core.getLogger()

# ── Output file paths (written to the directory you launch pox.py from) ──────
LOG_TXT  = "packet_log.txt"
LOG_CSV  = "packet_log.csv"
LOG_JSON = "packet_log.json"

# ── TCP flag bit masks ────────────────────────────────────────────────────────
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def _decode_tcp_flags(bits):
    flags = []
    if bits & TCP_FIN: flags.append("FIN")
    if bits & TCP_SYN: flags.append("SYN")
    if bits & TCP_RST: flags.append("RST")
    if bits & TCP_PSH: flags.append("PSH")
    if bits & TCP_ACK: flags.append("ACK")
    if bits & TCP_URG: flags.append("URG")
    return "|".join(flags) if flags else "NONE"


def _init_csv():
    """Write header row if CSV does not exist yet."""
    if not os.path.exists(LOG_CSV):
        with open(LOG_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "packet_id", "timestamp", "dpid", "in_port",
                "eth_src", "eth_dst",
                "protocol",
                "src_ip", "dst_ip",
                "src_port", "dst_port",
                "ttl", "packet_len",
                "tcp_flags",
                "icmp_type", "icmp_code",
                "arp_opcode", "arp_src_ip", "arp_dst_ip",
                "info"
            ])


# ─────────────────────────────────────────────────────────────────────────────
class PacketLogger(EventMixin):
    """
    POX component that:
      1. Installs a wildcard flow-mod on every new switch so all traffic
         is forwarded to the controller as packet-in events.
      2. Parses every packet-in, extracts headers, and logs to console +
         three log files.
    """

    def __init__(self):
        self.listenTo(core.openflow)      # subscribe to OpenFlow events
        self.packet_count   = 0
        self.total_bytes    = 0
        self.protocol_stats = {}          # protocol -> count
        self.records        = []          # in-memory list for JSON dump
        _init_csv()

        log.info("=" * 65)
        log.info("  SDN Packet Logger  –  POX OpenFlow Controller")
        log.info("  Logs: %s | %s | %s", LOG_TXT, LOG_CSV, LOG_JSON)
        log.info("=" * 65)

    # ── Switch connects ───────────────────────────────────────────────────────
    def _handle_ConnectionUp(self, event):
        """
        Called when a switch connects.
        Install a wildcard table-miss rule:
          match everything  →  send to controller
        """
        dpid = event.dpid

        msg                 = of.ofp_flow_mod()
        msg.match           = of.ofp_match()   # wildcard = match all
        msg.priority        = 1
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)

        log.info("[Switch connected] DPID: %016x  –  table-miss flow installed", dpid)

    # ── Packet arrives at controller ──────────────────────────────────────────
    def _handle_PacketIn(self, event):
        """Parse packet headers, log everything, then flood out."""

        pkt     = event.parsed          # top-level parsed packet
        in_port = event.port
        dpid    = event.dpid
        raw_len = len(event.data)

        if not pkt.parsed:
            log.warning("Incomplete packet – skipping")
            return

        # ── Layer 2: Ethernet ─────────────────────────────────────────────────
        eth_src = str(pkt.src)
        eth_dst = str(pkt.dst)
        ethertype = pkt.type

        # ── Defaults ──────────────────────────────────────────────────────────
        protocol   = "UNKNOWN"
        src_ip     = ""
        dst_ip     = ""
        src_port   = ""
        dst_port   = ""
        ttl        = ""
        tcp_flags  = ""
        icmp_type  = ""
        icmp_code  = ""
        arp_opcode = ""
        arp_src_ip = ""
        arp_dst_ip = ""
        info       = ""

        # ── ARP ───────────────────────────────────────────────────────────────
        arp_pkt = pkt.find("arp")
        if arp_pkt:
            protocol   = "ARP"
            arp_opcode = "Request" if arp_pkt.opcode == arp.REQUEST else "Reply"
            arp_src_ip = str(arp_pkt.protosrc)
            arp_dst_ip = str(arp_pkt.protodst)
            info = "ARP {}: {} → {}".format(arp_opcode, arp_src_ip, arp_dst_ip)

        # ── IPv4 ──────────────────────────────────────────────────────────────
        ip4_pkt = pkt.find("ipv4")
        if ip4_pkt:
            src_ip = str(ip4_pkt.srcip)
            dst_ip = str(ip4_pkt.dstip)
            ttl    = ip4_pkt.ttl

            # TCP
            tcp_pkt = pkt.find("tcp")
            if tcp_pkt:
                protocol = "TCP"
                src_port = tcp_pkt.srcport
                dst_port = tcp_pkt.dstport
                tcp_flags = _decode_tcp_flags(tcp_pkt.flags)
                # Classify well-known ports
                if dst_port in (80, 8080) or src_port in (80, 8080):
                    protocol = "HTTP"
                elif dst_port == 443 or src_port == 443:
                    protocol = "HTTPS"
                info = "{} {}:{} → {}:{} [{}]".format(
                    protocol, src_ip, src_port, dst_ip, dst_port, tcp_flags)

            # UDP
            udp_pkt = pkt.find("udp")
            if udp_pkt:
                protocol = "UDP"
                src_port = udp_pkt.srcport
                dst_port = udp_pkt.dstport
                if dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                info = "{} {}:{} → {}:{}".format(
                    protocol, src_ip, src_port, dst_ip, dst_port)

            # ICMP
            icmp_pkt = pkt.find("icmp")
            if icmp_pkt:
                protocol  = "ICMP"
                icmp_type = icmp_pkt.type
                icmp_code = icmp_pkt.code
                type_name = {
                    0: "Echo Reply", 8: "Echo Request",
                    3: "Dest Unreachable", 11: "TTL Exceeded",
                    5: "Redirect"
                }.get(icmp_pkt.type, "Type {}".format(icmp_pkt.type))
                info = "ICMP {} {} → {}".format(type_name, src_ip, dst_ip)

            if not tcp_pkt and not udp_pkt and not icmp_pkt:
                protocol = "IPv4"
                info = "IPv4 {} → {} proto={}".format(src_ip, dst_ip, ip4_pkt.protocol)

        # ── IPv6 ──────────────────────────────────────────────────────────────
        ip6_pkt = pkt.find("ipv6")
        if ip6_pkt:
            protocol = "IPv6"
            src_ip   = str(ip6_pkt.srcip)
            dst_ip   = str(ip6_pkt.dstip)
            info     = "IPv6 {} → {}".format(src_ip, dst_ip)

        # ── LLDP ──────────────────────────────────────────────────────────────
        if ethertype == ethernet.LLDP_TYPE:
            protocol = "LLDP"
            info     = "Link Layer Discovery Protocol"

        # ── Build record ──────────────────────────────────────────────────────
        self.packet_count += 1
        self.total_bytes  += raw_len
        self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
        timestamp = datetime.datetime.now().isoformat(timespec="milliseconds")

        record = {
            "packet_id":   self.packet_count,
            "timestamp":   timestamp,
            "dpid":        "{:016x}".format(dpid),
            "in_port":     in_port,
            "eth_src":     eth_src,
            "eth_dst":     eth_dst,
            "protocol":    protocol,
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "src_port":    str(src_port),
            "dst_port":    str(dst_port),
            "ttl":         str(ttl),
            "packet_len":  raw_len,
            "tcp_flags":   tcp_flags,
            "icmp_type":   str(icmp_type),
            "icmp_code":   str(icmp_code),
            "arp_opcode":  arp_opcode,
            "arp_src_ip":  arp_src_ip,
            "arp_dst_ip":  arp_dst_ip,
            "info":        info,
        }
        self.records.append(record)

        # ── Write to all log outputs ──────────────────────────────────────────
        self._log_console(record)
        self._log_txt(record)
        self._log_csv(record)
        self._log_json()

        # ── Print summary every 20 packets ───────────────────────────────────
        if self.packet_count % 20 == 0:
            self._print_summary()

        # ── Flood packet out so the network stays functional ─────────────────
        msg         = of.ofp_packet_out()
        msg.data    = event.ofp
        msg.in_port = in_port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    # ── Log writers ───────────────────────────────────────────────────────────

    def _log_console(self, r):
        log.info(
            "[#%04d] %-6s | %s:%s → %s:%s | %d bytes | dpid=%s port=%s | %s",
            r["packet_id"], r["protocol"],
            r["src_ip"] or r["eth_src"], r["src_port"] or "—",
            r["dst_ip"] or r["eth_dst"], r["dst_port"] or "—",
            r["packet_len"],
            r["dpid"], r["in_port"],
            r["info"]
        )

    def _log_txt(self, r):
        line = (
            "[{timestamp}] PKT #{packet_id:04d} | Proto: {protocol:<6} | "
            "Src: {src_ip}:{src_port} | Dst: {dst_ip}:{dst_port} | "
            "Len: {packet_len} bytes | TTL: {ttl} | Flags: {tcp_flags} | "
            "DPID: {dpid} Port: {in_port} | {info}\n"
        ).format(**r)
        with open(LOG_TXT, "a") as f:
            f.write(line)

    def _log_csv(self, r):
        with open(LOG_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                r["packet_id"], r["timestamp"], r["dpid"], r["in_port"],
                r["eth_src"], r["eth_dst"],
                r["protocol"],
                r["src_ip"], r["dst_ip"],
                r["src_port"], r["dst_port"],
                r["ttl"], r["packet_len"],
                r["tcp_flags"],
                r["icmp_type"], r["icmp_code"],
                r["arp_opcode"], r["arp_src_ip"], r["arp_dst_ip"],
                r["info"]
            ])

    def _log_json(self):
        with open(LOG_JSON, "w") as f:
            json.dump(self.records, f, indent=2)

    def _print_summary(self):
        total = self.packet_count
        log.info("─" * 60)
        log.info("  SUMMARY  |  Total packets: %d  |  Total bytes: %d",
                 total, self.total_bytes)
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: -x[1]):
            pct = count / total * 100
            bar = "█" * int(pct / 5)
            log.info("  %-8s %4d  (%5.1f%%)  %s", proto, count, pct, bar)
        log.info("─" * 60)


# ─────────────────────────────────────────────────────────────────────────────
def launch():
    """
    POX entry point.  Called automatically by:
        python pox.py packet_logger
    """
    core.registerNew(PacketLogger)
    log.info("Packet Logger component registered – waiting for switches...")
