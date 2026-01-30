class Window:
    def __init__(self, packets):
        self.packets = packets

    def update(self, packets):
        self.packets = packets
    
    def get_initial_window_byte(self):
        sorted_packets = sorted(self.packets, key=lambda pkt: float(pkt.sniff_timestamp))

        for pkt in sorted_packets:
            if not hasattr(pkt, "tcp"):
                continue

            try:
                return int(pkt.tcp.window_size_value)
            except Exception:
                return 0
        
        return 0