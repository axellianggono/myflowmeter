MyFlowMeter
===========
This project is a flow-based network traffic feature extractor inspired by
CICFlowMeter. It processes network packets (from PCAP files or live capture),
groups them into bidirectional flows, and extracts statistical features commonly
used in Intrusion Detection Systems (IDS) and network traffic analysis.

The main goal of this project is educational and research-oriented, focusing on
understanding how CICFlowMeter-style features are derived algorithmically and
implemented in practice using Python and PyShark.

Quick Start
-----------
* Capture a pcap file
* Run 
```bash
python main.py --source example.pcap --output example.log
```

Generated Features
------------------
+-------------------+---------------------------------------------------------------+
| Feature Name      | Description                                                   |
+-------------------+---------------------------------------------------------------+
| fl_dur            | Flow duration                                                 |
| tot_fw_pk         | Total packets in the forward direction                        |
| tot_bw_pk         | Total packets in the backward direction                       |
| tot_l_fw_pkt      | Total size of packets in the forward direction                |
| fw_pkt_l_max      | Maximum packet size in the forward direction                  |
| fw_pkt_l_min      | Minimum packet size in the forward direction                  |
| fw_pkt_l_avg      | Average packet size in the forward direction                  |
| fw_pkt_l_std      | Standard deviation of packet size (forward)                   |
| bw_pkt_l_max      | Maximum packet size in the backward direction                 |
| bw_pkt_l_min      | Minimum packet size in the backward direction                 |
| bw_pkt_l_avg      | Average packet size in the backward direction                 |
| bw_pkt_l_std      | Standard deviation of packet size (backward)                  |
| fl_byt_s          | Flow byte rate (bytes per second)                             |
| fl_pkt_s          | Flow packet rate (packets per second)                         |
| fl_iat_avg        | Average inter-arrival time between packets (flow)             |
| fl_iat_std        | Standard deviation of inter-arrival time (flow)               |
| fl_iat_max        | Maximum inter-arrival time (flow)                             |
| fl_iat_min        | Minimum inter-arrival time (flow)                             |
| fw_iat_tot        | Total inter-arrival time (forward)                            |
| fw_iat_avg        | Average inter-arrival time (forward)                          |
| fw_iat_std        | Standard deviation of inter-arrival time (forward)            |
| fw_iat_max        | Maximum inter-arrival time (forward)                          |
| fw_iat_min        | Minimum inter-arrival time (forward)                          |
| bw_iat_tot        | Total inter-arrival time (backward)                           |
| bw_iat_avg        | Average inter-arrival time (backward)                         |
| bw_iat_std        | Standard deviation of inter-arrival time (backward)           |
| bw_iat_max        | Maximum inter-arrival time (backward)                         |
| bw_iat_min        | Minimum inter-arrival time (backward)                         |
| fw_psh_flag       | PSH flag count in forward direction                           |
| bw_psh_flag       | PSH flag count in backward direction                          |
| fw_urg_flag       | URG flag count in forward direction                           |
| bw_urg_flag       | URG flag count in backward direction                          |
| fw_hdr_len        | Total header bytes in forward direction                       |
| bw_hdr_len        | Total header bytes in backward direction                      |
| fw_pkt_s          | Forward packets per second                                    |
| bw_pkt_s          | Backward packets per second                                   |
| pkt_len_min       | Minimum packet length in flow                                 |
| pkt_len_max       | Maximum packet length in flow                                 |
| pkt_len_avg       | Average packet length in flow                                 |
| pkt_len_std       | Standard deviation of packet length in flow                   |
| pkt_len_va        | Minimum packet inter-arrival time (flow)                      |
| fin_cnt           | FIN flag count                                                |
| syn_cnt           | SYN flag count                                                |
| rst_cnt           | RST flag count                                                |
| pst_cnt           | PSH flag count                                                |
| ack_cnt           | ACK flag count                                                |
| urg_cnt           | URG flag count                                                |
| cwe_cnt           | CWE flag count                                                |
| ece_cnt           | ECE flag count                                                |
| down_up_ratio     | Download/upload packet ratio                                  |
| pkt_size_avg      | Average packet size                                           |
| fw_seg_avg        | Average segment size in forward direction                     |
| bw_seg_avg        | Average segment size in backward direction                    |
| fw_byt_blk_avg    | Average bytes per bulk (forward)                              |
| fw_pkt_blk_avg    | Average packets per bulk (forward)                            |
| fw_blk_rate_avg   | Bulk rate per second (forward)                                |
| bw_byt_blk_avg    | Average bytes per bulk (backward)                             |
| bw_pkt_blk_avg    | Average packets per bulk (backward)                           |
| bw_blk_rate_avg   | Bulk rate per second (backward)                               |
| subfl_fw_pk       | Average packets per forward subflow                           |
| subfl_fw_byt      | Average bytes per forward subflow                             |
| subfl_bw_pkt      | Average packets per backward subflow                          |
| subfl_bw_byt      | Average bytes per backward subflow                            |
| fw_win_byt        | Initial TCP window size (forward)                             |
| bw_win_byt        | Initial TCP window size (backward)                            |
| Fw_act_pkt        | Forward TCP packets carrying payload                          |
| fw_seg_min        | Minimum TCP payload size in forward direction                 |
| atv_avg           | Average active time                                           |
| atv_std           | Standard deviation of active time                             |
| atv_max           | Maximum active time                                           |
| atv_min           | Minimum active time                                           |
| idl_avg           | Average idle time                                             |
| idl_std           | Standard deviation of idle time                               |
| idl_max           | Maximum idle time                                             |
| idl_min           | Minimum idle time                                             |
+-------------------+---------------------------------------------------------------+


References
----------
* https://www.unb.ca/cic/research/applications.html
* https://www.unb.ca/cic/datasets/ids-2018.html