class Bulk:
    """
    Bulk means there are N packets sent continuously in the same direction
    with small inter-arrival time.
    """

    def __init__(self, packets, bulk_min_packets=4, bulk_ia_threshold=1.0):
        self.packets = packets
        self.bulk_min_packets = bulk_min_packets
        self.bulk_ia_threshold = bulk_ia_threshold

        self.bytes_avg = 0 
        self.pkt_avg = 0 
        self.rate_avg = 0 

    def update(self, packets):
        self.packets = packets

    def _get_time(self, packet):
        if hasattr(packet, "sniff_timestamp"):
            return float(packet.sniff_timestamp)
        elif hasattr(packet, "frame_info"):
            return float(packet.frame_info.time_epoch)
        else:
            return None

    def _get_size(self, packet):
        try:
            return int(packet.length)
        except Exception:
            return 0

    def calculate(self, flow_duration):
        """
        flow_duration: total flow duration in seconds
        """

        if len(self.packets) < self.bulk_min_packets or flow_duration <= 0:
            self.bytes_avg = 0
            self.pkt_avg = 0
            self.rate_avg = 0
            return

        # sort packets by timestamp
        packets_sorted = sorted(
            self.packets,
            key=lambda pkt: self._get_time(pkt) or 0
        )

        bulk_packet_counts = []
        bulk_byte_counts = []

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

                if iat <= self.bulk_ia_threshold:
                    current_pkt_count += 1
                    current_byte_count += size
                else:
                    # finalize previous bulk
                    if current_pkt_count >= self.bulk_min_packets:
                        bulk_packet_counts.append(current_pkt_count)
                        bulk_byte_counts.append(current_byte_count)

                    current_pkt_count = 1
                    current_byte_count = size

            last_time = t

        # finalize last bulk
        if current_pkt_count >= self.bulk_min_packets:
            bulk_packet_counts.append(current_pkt_count)
            bulk_byte_counts.append(current_byte_count)

        bulk_count = len(bulk_packet_counts)

        if bulk_count > 0:
            self.pkt_avg = sum(bulk_packet_counts) / bulk_count
            self.bytes_avg = sum(bulk_byte_counts) / bulk_count
            self.rate_avg = bulk_count / flow_duration
        else:
            self.pkt_avg = 0
            self.bytes_avg = 0
            self.rate_avg = 0
