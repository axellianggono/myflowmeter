class Header:
    def __init__(self, packets=None):
        self.packets = packets if packets else []
        self.total_hdr_len = 0

    def add_packet_incremental(self, packet):
        """Incrementally add packet header length"""
        if hasattr(packet, "ip"):
            ip_hdr = int(packet.ip.hdr_len) * 4
        else:
            ip_hdr = 0

        if hasattr(packet, "tcp"):
            l4_hdr = int(packet.tcp.hdr_len) * 4
        elif hasattr(packet, "udp"):
            l4_hdr = 8
        else:
            l4_hdr = 0

        self.total_hdr_len += ip_hdr + l4_hdr

