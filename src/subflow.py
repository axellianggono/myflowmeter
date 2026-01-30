class Subflow:
    """
    Subflow splits a flow into smaller segments separated by idle time.
    """

    def __init__(self, packets, idle_threshold=1.0):
        self.packets = packets
        self.idle_threshold = idle_threshold

        self.packets_avg = 0 
        self.bytes_avg = 0 

    def update(self, packets):
        self.packets = packets

    def _get_time(self, packet):
        if hasattr(packet, "sniff_timestamp"):
            return float(packet.sniff_timestamp)
        elif hasattr(packet, "frame_info"):
            return float(packet.frame_info.time_epoch)
        else:
            return None

    def _get_size(self, pkt):
        try:
            return int(pkt.length)
        except Exception:
            return 0

    def calculate(self):
        if len(self.packets) == 0:
            self.packets_avg = 0
            self.bytes_avg = 0
            return

        # sort packets by timestamp
        packets_sorted = sorted(
            self.packets,
            key=lambda pkt: self._get_time(pkt) or 0
        )

        subflow_packet_counts = []
        subflow_byte_counts = []

        current_pkt_count = 0
        current_byte_count = 0
        last_time = None

        for pkt in packets_sorted:
            t = self._get_time(pkt)
            size = self._get_size(pkt)

            if t is None:
                continue

            if last_time is None:
                current_pkt_count = 1
                current_byte_count = size
            else:
                iat = t - last_time

                if iat <= self.idle_threshold:
                    # still same subflow
                    current_pkt_count += 1
                    current_byte_count += size
                else:
                    # subflow ended
                    subflow_packet_counts.append(current_pkt_count)
                    subflow_byte_counts.append(current_byte_count)

                    current_pkt_count = 1
                    current_byte_count = size

            last_time = t

        # finalize last subflow
        subflow_packet_counts.append(current_pkt_count)
        subflow_byte_counts.append(current_byte_count)

        subflow_count = len(subflow_packet_counts)

        if subflow_count > 0:
            self.packets_avg = sum(subflow_packet_counts) / subflow_count
            self.bytes_avg = sum(subflow_byte_counts) / subflow_count
        else:
            self.packets_avg = 0
            self.bytes_avg = 0
