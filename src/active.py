import math

class Active:
    def __init__(self, packets, active_time):
        self.packets = packets
        self.active_time = active_time

        self.avg = 0
        self.std = 0
        self.max = 0
        self.min = 0

    def update(self, packets):
        self.packets = packets

    def _get_time(self, packet):
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

        active_durations = []

        active_start = None
        last_time = None

        for pkt in packets_sorted:
            t = self._get_time(pkt)
            if t is None:
                continue

            if last_time is None:
                active_start = t
                last_time = t
                continue

            iat = t - last_time

            if iat <= self.active_time:
                # still active
                last_time = t
            else:
                # active ended
                active_durations.append(last_time - active_start)
                active_start = t
                last_time = t

        # finalize last active period
        if active_start is not None and last_time is not None:
            active_durations.append(last_time - active_start)

        if len(active_durations) == 0:
            self.avg = self.std = self.max = self.min = 0
            return

        self.avg = sum(active_durations) / len(active_durations)
        self.max = max(active_durations)
        self.min = min(active_durations)

        if len(active_durations) > 1:
            mean = self.avg
            self.std = math.sqrt(
                sum((x - mean) ** 2 for x in active_durations)
                / len(active_durations)
            )
        else:
            self.std = 0
