import math

class IAT:
    def __init__(self, packets=None):
        self.packets = packets if packets else []
        self.total_time = 0
        self.min = 0
        self.max = 0
        self.avg = 0
        self.std = 0

    def update_packets(self, packets):
        self.packets = packets

    def calculate(self):
        n = len(self.packets)

        if n < 2:
            self.min = 0
            self.max = 0
            self.avg = 0
            self.std = 0
            return

        times = sorted([float(pkt.sniff_timestamp) for pkt in self.packets])

        iats = [
            times[i] - times[i - 1]
            for i in range(1, len(times))
        ]

        self.total_time = sum(iats)
        self.min = min(iats)
        self.max = max(iats)
        self.avg = sum(iats) / len(iats)

        if len(iats) > 1:
            variance = sum(
                (iat - self.avg) ** 2 for iat in iats
            ) / len(iats)
            self.std = math.sqrt(variance)
        else:
            self.std = 0
