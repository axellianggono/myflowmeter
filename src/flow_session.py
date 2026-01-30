from src.flow import Flow

class FlowSession:
    def __init__(self, idle_timeout, active_timeout, label):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.label = label

        self.active_flow_dict = {}
        self.inactive_flow = []

    def _get_flow_key(self, packet):
        """Generate bidirectional flow key from packet"""
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet[packet.transport_layer].srcport
            dst_port = packet[packet.transport_layer].dstport
            protocol = packet.transport_layer
            
            # Create bidirectional key (order doesn't matter)
            key1 = (src_ip, dst_ip, src_port, dst_port, protocol)
            key2 = (dst_ip, src_ip, dst_port, src_port, protocol)
            
            return key1, key2
        except Exception:
            return None, None
    
    def _invalidate_flow(self, packet):
        """Remove expired flows based on idle and active timeouts"""
        expired = []
        expired_keys = []
        current_time = float(packet.sniff_timestamp)

        # Collect expired flows
        for key, flow in self.active_flow_dict.items():
            if current_time - flow.end_time > self.idle_timeout:
                expired.append(flow)
                expired_keys.append(key)
            elif current_time - flow.start_time > self.active_timeout:
                expired.append(flow)
                expired_keys.append(key)

        # Remove expired flows from active dict
        for key in expired_keys:
            del self.active_flow_dict[key]
            
        # Move to inactive list
        self.inactive_flow.extend(expired)

        return expired

    def _get_packet_flow(self, packet):
        """Fast O(1) flow lookup using dictionary"""
        key1, key2 = self._get_flow_key(packet)
        
        if key1 is None:
            return None, None
            
        # Check both directions
        if key1 in self.active_flow_dict:
            return self.active_flow_dict[key1], key1
        elif key2 in self.active_flow_dict:
            return self.active_flow_dict[key2], key2
            
        return None, None

    def process_packet(self, packet):
        """Process packet and update corresponding flow"""
        invalidated_flow = self._invalidate_flow(packet)
        flow, flow_key = self._get_packet_flow(packet)
        
        if flow:
            flow.update_flow(packet)
        else:
            # Create new flow
            new_flow = Flow(packet, self.active_timeout, self.idle_timeout, self.label)
            key1, _ = self._get_flow_key(packet)
            if key1:
                self.active_flow_dict[key1] = new_flow
        
        return invalidated_flow

    def _close_all_flow(self):
        """Close all active flows"""
        self.inactive_flow.extend(self.active_flow_dict.values())
        self.active_flow_dict.clear()

    def get_all_flow(self):
        """Get all inactive flows"""
        return self.inactive_flow
    
    
    
