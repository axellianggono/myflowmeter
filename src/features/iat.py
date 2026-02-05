import math

class IAT:
    def __init__(self, packets=None):
        self.packets = packets if packets else []
        self.total_time = 0
        self.min = 0
        self.max = 0
        self.avg = 0
        self.std = 0
        
        # Incremental IAT tracking
        self._last_timestamp = None
        self._count = 0
        self._m2 = 0

    def add_packet_incremental(self, timestamp):
        """Incrementally update IAT statistics with new packet timestamp"""
        timestamp = float(timestamp)
        
        if self._last_timestamp is None:
            self._last_timestamp = timestamp
            return
        
        # Calculate IAT from last packet
        iat = timestamp - self._last_timestamp
        self._last_timestamp = timestamp
        
        self._count += 1
        self.total_time += iat
        
        # Update min/max
        if self._count == 1:
            self.min = iat
            self.max = iat
        else:
            self.min = min(self.min, iat)
            self.max = max(self.max, iat)
        
        # Welford's algorithm for running mean and variance
        delta = iat - self.avg
        self.avg += delta / self._count
        delta2 = iat - self.avg
        self._m2 += delta * delta2
        
        # Update std
        if self._count > 1:
            variance = self._m2 / self._count
            self.std = math.sqrt(variance)
        else:
            self.std = 0

