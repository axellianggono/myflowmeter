class Window:
    def __init__(self, packets):
        self.packets = packets
        self._initial_window = None

    def add_packet_incremental(self, packet):
        """Store initial TCP window size from first TCP packet"""
        if self._initial_window is None and hasattr(packet, "tcp"):
            try:
                self._initial_window = int(packet.tcp.window_size_value)
            except Exception:
                self._initial_window = 0
    
    def get_initial_window_byte(self):
        """Return cached initial window size"""
        return self._initial_window if self._initial_window is not None else 0
