from src.packet_size import PacketSize
from src.iat import IAT
from src.flag import Flag
from src.header import Header
from src.bulk import Bulk
from src.subflow import Subflow
from src.window import Window
from src.active import Active
from src.idle import Idle

class Flow:
    def __init__(self, packet, active_timout, idle_timeout, label):
        self.packets = [(packet, "FWD")]

        self._all_packets = self._get_all_packets()
        self._fw_packets = self._get_forward_packets()
        self._bw_packets = self._get_backward_packets()

        self.active_timeout = active_timout
        self.idle_timeout = idle_timeout
        
        self.label = label
        
        self.src_ip = packet.ip.src
        self.dst_ip = packet.ip.dst
        self.src_port = packet[packet.transport_layer].srcport
        self.dst_port = packet[packet.transport_layer].dstport
        self.protocol = packet.transport_layer
        self.start_time = float(packet.sniff_timestamp)
        self.end_time = float(packet.sniff_timestamp)
        
        self.flow_duration = self.start_time - self.end_time
        self.total_fwd_packets = 1
        self.total_bwd_packets = 0

        self.flow_packet_size = PacketSize(self._all_packets)
        self.fw_packet_size = PacketSize(self._fw_packets)
        self.bw_packet_size = PacketSize(self._bw_packets)

        self.flow_byte_per_sec = 0
        self.flow_packet_per_sec = 0

        self.flow_iat = IAT(self._all_packets)
        self.fw_iat = IAT(self._fw_packets)
        self.bw_iat = IAT(self._bw_packets)

        self.flags = Flag(self._all_packets)

        self.fw_header = Header(self._all_packets)
        self.bw_header = Header(self._all_packets)

        self.forward_packet_per_sec = 0
        self.backward_packet_per_sec = 0
        self.down_up_ratio = 0

        self.fw_seg_avg = 0
        self.bw_seg_avg = 0

        self.fw_bulk = Bulk(self._fw_packets)
        self.bw_bulk = Bulk(self._bw_packets)

        self.fw_subflow = Subflow(self._fw_packets)
        self.bw_subflow = Subflow(self._bw_packets)

        self.fw_window = Window(self._fw_packets)
        self.bw_window = Window(self._bw_packets)

        self.fw_active_packet = 0

        self.fw_seg_min = None

        self.active = Active(self._all_packets, active_timout)
        self.idle = Idle(self._all_packets, idle_timeout)

    def _get_all_packets(self):
        return [packet[0] for packet in self.packets]

    def _get_forward_packets(self):
        return [packet[0] for packet in self.packets if packet[1] == "FWD"]

    def _get_backward_packets(self):
        return [packet[0] for packet in self.packets if packet[1] == "BWD"]

    def _is_active_packet(self, packet):
        if not hasattr(packet, "tcp") or not hasattr(packet, "ip"):
            return False

        try:
            ip_hdr_len = int(packet.ip.hdr_len) * 4
            tcp_hdr_len = int(packet.tcp.hdr_len) * 4
            total_len = int(packet.length)

            payload_len = total_len - ip_hdr_len - tcp_hdr_len

            return payload_len > 0

        except Exception:
            return False

    def _get_payload_len(self, packet):
        if not hasattr(packet, "tcp") or not hasattr(packet, "ip"):
            return 0

        try:
            ip_hdr = int(packet.ip.hdr_len) * 4
            tcp_hdr = int(packet.tcp.hdr_len) * 4
            total_len = int(packet.length)
            return max(0, total_len - ip_hdr - tcp_hdr)
        except Exception:
            return 0

    def update_flow(self, packet):
        self.end_time = float(packet.sniff_timestamp)
        self.flow_duration = self.end_time - self.start_time

        if packet.ip.src == self.src_ip and packet.ip.dst == self.dst_ip:
            self.total_fwd_packets += 1
            self.packets.append((packet, "FWD"))

            if self._is_active_packet(packet):
                self.fw_active_packet += 1

            payload_len = self._get_payload_len(packet)

            if payload_len > 0:
                if self.fw_seg_min is None or payload_len < self.fw_seg_min:
                    self.fw_seg_min = payload_len
        else:
            self.total_bwd_packets += 1
            self.packets.append((packet, "BWD"))

    def get_feature(self):
        self._all_packets = self._get_all_packets()
        self._fw_packets = self._get_forward_packets()
        self._bw_packets = self._get_backward_packets()

        self.fw_packet_size.update_packets(self._fw_packets)
        self.bw_packet_size.update_packets(self._bw_packets)
        self.flow_iat.update_packets(self._all_packets)
        self.fw_iat.update_packets(self._fw_packets)
        self.bw_iat.update_packets(self._bw_packets)
        self.flags.update(self._all_packets)
        self.fw_header.update(self._fw_packets)
        self.bw_header.update(self._bw_packets)
        self.flow_packet_size.update_packets(self._all_packets)
        self.fw_bulk.update(self._fw_packets)
        self.bw_bulk.update(self._bw_packets)
        self.fw_window.update(self._fw_packets)
        self.bw_window.update(self._bw_packets)
        self.active.update(self._all_packets)
        self.idle.update(self._all_packets)

        self.fw_packet_size.calculate()
        self.bw_packet_size.calculate()
        self.flow_iat.calculate()
        self.fw_iat.calculate()
        self.bw_iat.calculate()
        self.flags.calculate()
        self.fw_header.calculate()
        self.bw_header.calculate()
        self.flow_packet_size.calculate()
        self.fw_bulk.calculate(self.flow_duration)
        self.bw_bulk.calculate(self.flow_duration)
        self.active.calculate()

        self.flow_duration = self.end_time - self.start_time

        if self.flow_duration != 0:
            self.flow_byte_per_sec = self.fw_packet_size.total_size_pkt / self.flow_duration
            self.flow_packet_per_sec = self.total_fwd_packets / self.flow_duration
            self.forward_packet_per_sec = self.total_fwd_packets / self.flow_duration
            self.backward_packet_per_sec = self.total_bwd_packets / self.flow_duration
            self.down_up_ratio = self.total_bwd_packets / self.total_fwd_packets
        
        self.fw_seg_avg = self.fw_packet_size.total_size_pkt / self.total_fwd_packets if self.total_fwd_packets != 0 else 0
        self.bw_seg_avg = self.bw_packet_size.total_size_pkt / self.total_bwd_packets if self.total_bwd_packets != 0 else 0

        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "flow_duration": self.flow_duration,
            "total_fwd_packets": self.total_fwd_packets,
            "total_bwd_packets": self.total_bwd_packets,
            "fw_packet_size": self.fw_packet_size.total_size_pkt,
            "fw_packet_size_max": self.fw_packet_size.max_size_pkt,
            "fw_packet_size_min": self.fw_packet_size.min_size_pkt,
            "fw_packet_size_avg": self.fw_packet_size.avg_size_pkt,
            "fw_packet_size_std": self.fw_packet_size.std_size_pkt,
            "bw_packet_size": self.bw_packet_size.total_size_pkt,
            "bw_packet_size_max": self.bw_packet_size.max_size_pkt,
            "bw_packet_size_min": self.bw_packet_size.min_size_pkt,
            "bw_packet_size_avg": self.bw_packet_size.avg_size_pkt,
            "bw_packet_size_std": self.bw_packet_size.std_size_pkt,
            "flow_byte_per_sec": self.flow_byte_per_sec,
            "flow_packet_per_sec": self.flow_packet_per_sec,
            "flow_iat_avg": self.flow_iat.avg,
            "flow_iat_std": self.flow_iat.std,
            "flow_iat_max": self.flow_iat.max,
            "flow_iat_min": self.flow_iat.min,
            "fw_iat_total": self.fw_iat.total_time,
            "fw_iat_avg": self.fw_iat.avg,
            "fw_iat_std": self.fw_iat.std,
            "fw_iat_max": self.fw_iat.max,
            "fw_iat_min": self.fw_iat.min,
            "bw_iat_total": self.bw_iat.total_time,
            "bw_iat_avg": self.bw_iat.avg,
            "bw_iat_std": self.bw_iat.std,
            "bw_iat_max": self.bw_iat.max,
            "bw_iat_min": self.bw_iat.min,
            "fw_psh_flag": self.flags.psh_flag_cnt,
            "bw_psh_flag": self.flags.psh_flag_cnt,
            "fw_urg_flag": self.flags.urg_flag_cnt,
            "bw_urg_flag": self.flags.urg_flag_cnt,
            "fw_hdr_len": self.fw_header.total_hdr_len,
            "bw_hdr_len": self.bw_header.total_hdr_len,
            "fw_pkt_s": self.forward_packet_per_sec,
            "bw_pkt_s": self.backward_packet_per_sec,
            "pkt_len_min": self.flow_packet_size.min_size_pkt,
            "pkt_len_max": self.flow_packet_size.max_size_pkt,
            "pkt_len_avg": self.flow_packet_size.avg_size_pkt,
            "pkt_len_std": self.flow_packet_size.std_size_pkt,
            "pkt_len_va": self.flow_iat.min,
            "fin_cnt": self.flags.fin_flag_cnt,
            "syn_cnt": self.flags.syn_flag_cnt,
            "rst_cnt": self.flags.rst_flag_cnt,
            "push_cnt": self.flags.push_flag_cnt,
            "ack_cnt": self.flags.ack_flag_cnt,
            "urg_cnt": self.flags.urg_flag_cnt,
            "cwe_cnt": self.flags.cwe_flag_cnt,
            "ece_cnt": self.flags.ece_flag_cnt,
            "down_up_ratio": self.down_up_ratio,
            "pkt_size_avr": self.flow_packet_size.avg_size_pkt,
            "fw_seg_avg": self.fw_seg_avg,
            "bw_seg_avg": self.bw_seg_avg,
            "fw_byt_blk_avg": self.fw_bulk.bytes_avg,
            "fw_pkt_blk_avg": self.fw_bulk.pkt_avg,
            "fw_blk_rate_avg": self.fw_bulk.rate_avg,
            "bw_byt_blk_avg": self.bw_bulk.bytes_avg,
            "bw_pkt_blk_avg": self.bw_bulk.pkt_avg,
            "bw_blk_rate_avg": self.bw_bulk.rate_avg,
            "subfl_fw_pk": self.fw_subflow.packets_avg,
            "subfl_fw_byt": self.fw_subflow.bytes_avg,
            "subfl_bw_pk": self.bw_subflow.packets_avg,
            "subfl_bw_byt": self.bw_subflow.bytes_avg,
            "fw_win_byt": self.fw_window.get_initial_window_byte(),
            "bw_win_byt": self.bw_window.get_initial_window_byte(),
            "Fw_act_pkt": self.fw_active_packet,
            "fw_seg_min": self.fw_seg_min,
            "atv_avg": self.active.avg,
            "atv_std": self.active.std,
            "atv_max": self.active.max,
            "atv_min": self.active.min,
            "idl_avg": self.idle.avg,
            "idl_std": self.idle.std,
            "idl_max": self.idle.max,
            "idl_min": self.idle.min,
            "label": self.label,
        }