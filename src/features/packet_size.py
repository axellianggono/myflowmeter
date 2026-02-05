import math

class PacketSize:
    def __init__(self, packets):
        self.packets = packets
        self.total_size_pkt = 0
        self.max_size_pkt = 0
        self.min_size_pkt = 0
        self.avg_size_pkt = 0
        self.std_size_pkt = 0
        
        # For incremental statistics (Welford's algorithm)
        self._count = 0
        self._m2 = 0  # Sum of squared differences from mean

    def update_packets(self, packets):
        """Update packet list reference"""
        self.packets = packets

    def add_packet_incremental(self, packet_size):
        """Incrementally update statistics with new packet (Welford's algorithm)"""
        self._count += 1
        
        # Update min/max
        if self._count == 1:
            self.min_size_pkt = packet_size
            self.max_size_pkt = packet_size
        else:
            self.min_size_pkt = min(self.min_size_pkt, packet_size)
            self.max_size_pkt = max(self.max_size_pkt, packet_size)
        
        # Update total
        self.total_size_pkt += packet_size
        
        # Welford's algorithm for running mean and variance
        delta = packet_size - self.avg_size_pkt
        self.avg_size_pkt += delta / self._count
        delta2 = packet_size - self.avg_size_pkt
        self._m2 += delta * delta2
        
        # Update std
        if self._count > 1:
            variance = self._m2 / self._count
            self.std_size_pkt = math.sqrt(variance)
        else:
            self.std_size_pkt = 0

    def calculate(self):
        """Full recalculation (fallback for compatibility)"""
        if len(self.packets) == 0:
            self.total_size_pkt = 0
            self.max_size_pkt = 0
            self.min_size_pkt = 0
            self.avg_size_pkt = 0
            self.std_size_pkt = 0
            self._count = 0
            self._m2 = 0
            return

        sizes = [int(pkt.length) for pkt in self.packets]

        self.total_size_pkt = sum(sizes)
        self.max_size_pkt = max(sizes)
        self.min_size_pkt = min(sizes)
        self.avg_size_pkt = self.total_size_pkt / len(sizes)
        self._count = len(sizes)

        if len(sizes) > 1:
            variance = sum(
                (s - self.avg_size_pkt) ** 2 for s in sizes
            ) / len(sizes)
            self.std_size_pkt = math.sqrt(variance)
            self._m2 = variance * len(sizes)
        else:
            self.std_size_pkt = 0
            self._m2 = 0
