import math

class Active:
    """
    Active period tracking - tracks periods when packets arrive within active_time threshold.
    Online incremental version using Welford's algorithm.
    """
    
    def __init__(self, packets, active_time):
        self.packets = packets
        self.active_time = active_time

        self.avg = 0
        self.std = 0
        self.max = 0
        self.min = 0
        
        # Incremental tracking
        self._last_timestamp = None
        self._active_start = None
        
        # Welford's algorithm for active duration statistics
        self._active_count = 0
        self._m2 = 0

    def add_packet_incremental(self, timestamp):
        """Incrementally track active periods"""
        timestamp = float(timestamp)
        
        if self._last_timestamp is None:
            # First packet - start active period
            self._active_start = timestamp
            self._last_timestamp = timestamp
            return
        
        iat = timestamp - self._last_timestamp
        
        if iat <= self.active_time:
            # Still active
            pass
        else:
            # Active period ended - finalize it
            self._finalize_active_period()
            
            # Start new active period
            self._active_start = timestamp
        
        self._last_timestamp = timestamp
    
    def _finalize_active_period(self):
        """Finalize current active period"""
        if self._active_start is None or self._last_timestamp is None:
            return
        
        duration = self._last_timestamp - self._active_start
        
        if duration <= 0:
            return
        
        self._active_count += 1
        
        # Update min/max
        if self._active_count == 1:
            self.min = duration
            self.max = duration
        else:
            self.min = min(self.min, duration)
            self.max = max(self.max, duration)
        
        # Welford's algorithm for mean and variance
        delta = duration - self.avg
        self.avg += delta / self._active_count
        delta2 = duration - self.avg
        self._m2 += delta * delta2
        
        # Update std
        if self._active_count > 1:
            variance = self._m2 / self._active_count
            self.std = math.sqrt(variance)
        else:
            self.std = 0
    
    def finalize(self):
        """Finalize last active period"""
        self._finalize_active_period()

