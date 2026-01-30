import math

class Idle:
    def __init__(self, packets, idle_time):
        self.packets = packets
        self.idle_time = idle_time

        self.avg = 0
        self.std = 0
        self.max = 0
        self.min = 0

    def update(self, packets):
        self.packets = packets

    def _get_time(self, pkt):
        packet = pkt[0]
        if hasattr(packet, "sniff_timestamp"):
            return float(packet.sniff_timestamp)
        elif hasattr(packet, "frame_info"):
            return float(packet.frame_info.time_epoch)
        else:
            return None

    def calculate(self):
        if len(self.packets) < 2:
            self.avg = self.std = self.max = self.min = 0
            return

        packets_sorted = sorted(
            self.packets,
            key=lambda pkt: self._get_time(pkt) or 0
        )

        idle_durations = []

        last_time = None

        for pkt in packets_sorted:
            t = self._get_time(pkt)
            if t is None:
                continue

            if last_time is None:
                last_time = t
                continue

            iat = t - last_time

            if iat > self.idle_time:
                idle_durations.append(iat)

            last_time = t

        if len(idle_durations) == 0:
            self.avg = self.std = self.max = self.min = 0
            return

        self.avg = sum(idle_durations) / len(idle_durations)
        self.max = max(idle_durations)
        self.min = min(idle_durations)

        if len(idle_durations) > 1:
            mean = self.avg
            self.std = math.sqrt(
                sum((x - mean) ** 2 for x in idle_durations)
                / len(idle_durations)
            )
        else:
            self.std = 0
