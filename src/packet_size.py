import math

class PacketSize:
    def __init__(self, packets):
        self.packets = packets
        self.total_size_pkt = 0
        self.max_size_pkt = 0
        self.min_size_pkt = 0
        self.avg_size_pkt = 0
        self.std_size_pkt = 0

    def update_packets(self, packets):
        self.packets = packets

    def calculate(self):
        if len(self.packets) == 0:
            self.total_size_pkt = 0
            self.max_size_pkt = 0
            self.min_size_pkt = 0
            self.avg_size_pkt = 0
            self.std_size_pkt = 0
            return

        sizes = [int(pkt.length) for pkt in self.packets]

        self.total_size_pkt = sum(sizes)
        self.max_size_pkt = max(sizes)
        self.min_size_pkt = min(sizes)
        self.avg_size_pkt = self.total_size_pkt / len(sizes)

        if len(sizes) > 1:
            variance = sum(
                (s - self.avg_size_pkt) ** 2 for s in sizes
            ) / len(sizes)
            self.std_size_pkt = math.sqrt(variance)
        else:
            self.std_size_pkt = 0
