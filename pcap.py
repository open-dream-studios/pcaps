import pyshark

i = 0
cap = pyshark.FileCapture("250203.pcapng")
for packet in cap:
    if i == 0:
        i += 1

        # Layer ETH
        if "eth" in packet:
            eth_source = packet.eth.src
            eth_dest = packet.eth.dst
            eth_type = packet.eth.type

        # Layer IP
        if "IP" in packet:
            ip_version = packet.ip.version
            ip_hdr_len = packet.ip.hdr_len
            ip_dsfield = packet.ip.dsfield
            ip_dsfield.dscp = packet.ip.dsfield.dscp
            ip_dsfield.ecn = packet.ip.dsfield.ecn
            ip_len = packet.ip.len
            ip_id = packet.ip.id
            ip_flags = packet.ip.flags
            ip_flags.rb = packet.ip.flags.rb
            ip_flags.df = packet.ip.flags.df
            ip_flags.mf = packet.ip.flags.mf
            ip_frag_offset = packet.ip.frag_offset
            ip_ttl = packet.ip.ttl
            ip_proto = packet.ip.proto
            ip_checksum = packet.ip.checksum
            ip_checksum.status = packet.ip.checksum.status
            ip_src = packet.ip.src
            ip_addr = packet.ip.addr
            ip_src_host = packet.ip.src_host
            ip_host = packet.ip.host
            ip_dst = packet.ip.dst
            ip_dst_host = packet.ip.dst_host

        # Layer UDP
        if "UDP" in packet:
            udp_srcport = packet.udp.srcport
            udp_dstport = packet.udp.dstport
            udp_port = packet.udp.port
            udp_length = packet.udp.length
            udp_checksum = packet.udp.checksum
            udp_checksum.status = packet.udp.checksum.status
            udp_stream = packet.udp.stream
            udp_time_relative = packet.udp.time_relative
            udp_time_delta = packet.udp.time_delta

        # Layer BVLC
        if "BVLC" in packet:
            bvlc_type = packet.bvlc.type
            bvlc_function = packet.bvlc.function
            bvlc_length = packet.bvlc.length
            bvlc_fwd_ip = packet.bvlc.fwd_ip
            bvlc_fwd_port = packet.bvlc.fwd_port

        # Layer BACNET
        if "BACNET" in packet:
            bacnet_version = packet.bacnet.version
            bacnet_control = packet.bacnet.control
            bacnet_control_net = packet.bacnet.control_net
            bacnet_control_res1 = packet.bacnet.control_res1
            bacnet_control_dest = packet.bacnet.control_dest
            bacnet_control_res2 = packet.bacnet.control_res2
            bacnet_control_src = packet.bacnet.control_src
            bacnet_control_expect = packet.bacnet.control_expect
            bacnet_control_prio_high = packet.bacnet.control_prio_high
            bacnet_control_prio_low = packet.bacnet.control_prio_low
            bacnet_dnet = packet.bacnet.dnet
            bacnet_dlen = packet.bacnet.dlen
            bacnet_hopc = packet.bacnet.hopc

        # Layer BACAPP
        if "BACAPP" in packet:
                bacapp_type = packet.bacapp.type
                bacapp_unconfirmed_service = packet.bacapp.unconfirmed_service
                bacapp_who_is_low_limit = packet.bacapp.who_is.low_limit
                # "": "Context Tag: 0, Length/Value/Type: 2",
                bacapp_tag_class = packet.bacapp.tag_class
                bacapp_context_tag_number = packet.bacapp.context_tag_number
                bacapp_LVT = packet.bacapp.LVT
                bacapp_who_is_high_limit = packet.bacapp.who_is.high_limit
            
# EXTRACT OBJECT FIELD NAMES
# for field in dir(packet.bacapp):
#     if not field.startswith('__'):  # Skip special methods
#         try:
#             value = getattr(packet.bacapp, field)
#             print(f"{field}: {value}")
#         except AttributeError:
#             print(f"AttributeError accessing {field}")
