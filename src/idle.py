import math

class Idle:
    """
    Idle period tracking - tracks periods when IAT exceeds idle_time threshold.
    Online incremental version using Welford's algorithm.
    """
    
    def __init__(self, packets, idle_time):
        self.packets = packets
        self.idle_time = idle_time

        self.avg = 0
        self.std = 0
        self.max = 0
        self.min = 0
        
        # Incremental tracking
        self._last_timestamp = None
        
        # Welford's algorithm for idle duration statistics
        self._idle_count = 0
        self._m2 = 0

    def add_packet_incremental(self, timestamp):
        """Incrementally track idle periods"""
        timestamp = float(timestamp)
        
        if self._last_timestamp is None:
            self._last_timestamp = timestamp
            return
        
        iat = timestamp - self._last_timestamp
        
        if iat > self.idle_time:
            # This is an idle period
            self._idle_count += 1
            
            # Update min/max
            if self._idle_count == 1:
                self.min = iat
                self.max = iat
            else:
                self.min = min(self.min, iat)
                self.max = max(self.max, iat)
            
            # Welford's algorithm for mean and variance
            delta = iat - self.avg
            self.avg += delta / self._idle_count
            delta2 = iat - self.avg
            self._m2 += delta * delta2
            
            # Update std
            if self._idle_count > 1:
                variance = self._m2 / self._idle_count
                self.std = math.sqrt(variance)
            else:
                self.std = 0
        
        self._last_timestamp = timestamp

