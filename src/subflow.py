import math

class Subflow:
    """
    Subflow splits a flow into smaller segments separated by idle time.
    Online incremental version using Welford's algorithm.
    """

    def __init__(self, packets, idle_threshold=1.0):
        self.packets = packets
        self.idle_threshold = idle_threshold

        self.packets_avg = 0 
        self.bytes_avg = 0
        
        # Incremental tracking
        self._last_timestamp = None
        self._current_pkt_count = 0
        self._current_byte_count = 0
        
        # Welford's algorithm for subflow statistics
        self._subflow_count = 0
        self._pkt_m2 = 0
        self._byte_m2 = 0

    def add_packet_incremental(self, timestamp, packet_size):
        """Incrementally update subflow statistics"""
        timestamp = float(timestamp)
        
        if self._last_timestamp is None:
            # First packet - start first subflow
            self._current_pkt_count = 1
            self._current_byte_count = packet_size
            self._last_timestamp = timestamp
            return
        
        iat = timestamp - self._last_timestamp
        
        if iat <= self.idle_threshold:
            # Still same subflow
            self._current_pkt_count += 1
            self._current_byte_count += packet_size
        else:
            # Subflow ended - finalize current subflow stats
            self._finalize_current_subflow()
            
            # Start new subflow
            self._current_pkt_count = 1
            self._current_byte_count = packet_size
        
        self._last_timestamp = timestamp
    
    def _finalize_current_subflow(self):
        """Finalize current subflow and update running statistics"""
        if self._current_pkt_count == 0:
            return
        
        self._subflow_count += 1
        
        # Welford's algorithm for packets_avg
        delta_pkt = self._current_pkt_count - self.packets_avg
        self.packets_avg += delta_pkt / self._subflow_count
        delta2_pkt = self._current_pkt_count - self.packets_avg
        self._pkt_m2 += delta_pkt * delta2_pkt
        
        # Welford's algorithm for bytes_avg
        delta_byte = self._current_byte_count - self.bytes_avg
        self.bytes_avg += delta_byte / self._subflow_count
        delta2_byte = self._current_byte_count - self.bytes_avg
        self._byte_m2 += delta_byte * delta2_byte
    
    def finalize(self):
        """Finalize last subflow when flow ends"""
        self._finalize_current_subflow()

