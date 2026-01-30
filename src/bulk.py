import math

class Bulk:
    """
    Bulk means there are N packets sent continuously in the same direction
    with small inter-arrival time. Online incremental version.
    """

    def __init__(self, packets, bulk_min_packets=4, bulk_ia_threshold=1.0):
        self.packets = packets
        self.bulk_min_packets = bulk_min_packets
        self.bulk_ia_threshold = bulk_ia_threshold

        self.bytes_avg = 0 
        self.pkt_avg = 0 
        self.rate_avg = 0
        
        # Incremental tracking
        self._last_timestamp = None
        self._current_pkt_count = 0
        self._current_byte_count = 0
        
        # Welford's algorithm for bulk statistics
        self._bulk_count = 0
        self._pkt_m2 = 0
        self._byte_m2 = 0

    def add_packet_incremental(self, timestamp, packet_size):
        """Incrementally track bulk transfers"""
        timestamp = float(timestamp)
        
        if self._last_timestamp is None:
            # First packet
            self._current_pkt_count = 1
            self._current_byte_count = packet_size
            self._last_timestamp = timestamp
            return
        
        iat = timestamp - self._last_timestamp
        
        if iat <= self.bulk_ia_threshold:
            # Continue current bulk
            self._current_pkt_count += 1
            self._current_byte_count += packet_size
        else:
            # Bulk ended - finalize if it meets minimum threshold
            self._finalize_current_bulk()
            
            # Start new potential bulk
            self._current_pkt_count = 1
            self._current_byte_count = packet_size
        
        self._last_timestamp = timestamp
    
    def _finalize_current_bulk(self):
        """Finalize current bulk if it meets minimum criteria"""
        if self._current_pkt_count < self.bulk_min_packets:
            return
        
        self._bulk_count += 1
        
        # Welford's algorithm for pkt_avg
        delta_pkt = self._current_pkt_count - self.pkt_avg
        self.pkt_avg += delta_pkt / self._bulk_count
        delta2_pkt = self._current_pkt_count - self.pkt_avg
        self._pkt_m2 += delta_pkt * delta2_pkt
        
        # Welford's algorithm for bytes_avg
        delta_byte = self._current_byte_count - self.bytes_avg
        self.bytes_avg += delta_byte / self._bulk_count
        delta2_byte = self._current_byte_count - self.bytes_avg
        self._byte_m2 += delta_byte * delta2_byte
    
    def finalize(self, flow_duration):
        """Finalize last bulk and compute rate"""
        self._finalize_current_bulk()
        
        if self._bulk_count > 0 and flow_duration > 0:
            self.rate_avg = self._bulk_count / flow_duration
        else:
            self.rate_avg = 0

