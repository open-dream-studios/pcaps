import pyshark


def mac_to_ip(mac_address):
    mac_parts = mac_address.split(":")
    ip_parts = [str(int(part, 16)) for part in mac_parts]
    ip_address = ".".join(ip_parts)
    # print(ip_address)
    # print(".".join(ip_address.split(".")[0:4]))
    return ".".join(ip_address.split(".")[0:4])


cap = pyshark.FileCapture("files/D4-250203.pcapng")
pcap_rows = {}

for i, packet in enumerate(cap):
    row = {}
    row["packet"] = packet

    if i == 0:
        # print(packet)
        # Layer ETH
        if "eth" in packet:
            eth_source = packet.eth.src
            eth_dest = packet.eth.dst
            eth_type = packet.eth.type

            row["eth_src"] = eth_source
            row["eth_dst"] = eth_dest
            row["eth_type"] = eth_type

        # Layer IP
        if "IP" in packet:
            # # print(packet.ip.dsfield)
            # ip_version = packet.ip.version
            # ip_hdr_len = packet.ip.hdr_len
            # ip_dsfield = packet.ip.dsfield
            # # ip_dsfield_dscp = packet.ip.dsfield.dscp
            # # ip_dsfield_ecn = packet.ip.dsfield.ecn
            # ip_len = packet.ip.len
            # ip_id = packet.ip.id
            # ip_flags = packet.ip.flags
            # # ip_flags_rb = packet.ip.flags.rb
            # # ip_flags_df = packet.ip.flags.df
            # # ip_flags_mf = packet.ip.flags.mf
            # ip_frag_offset = packet.ip.frag_offset
            # ip_ttl = packet.ip.ttl
            # ip_proto = packet.ip.proto
            # ip_checksum = packet.ip.checksum
            # # ip_checksum_status = packet.ip.checksum.status
            ip_src = packet.ip.src
            # ip_addr = packet.ip.addr
            # ip_src_host = packet.ip.src_host
            # ip_host = packet.ip.host
            ip_dst = packet.ip.dst
            # ip_dst_host = packet.ip.dst_host

            #     row.append(ip_version)
            #     row.append(ip_hdr_len)
            #     row.append(ip_dsfield)
            #     # row.append(ip_dsfield_dscp)
            #     # row.append(ip_dsfield_ecn)
            #     # row.append(ip_len)
            #     row.append(ip_id)
            #     row.append(ip_flags)
            #     # row.append(ip_flags_rb)
            #     # row.append(ip_flags_df)
            #     # row.append(ip_flags_mf)
            #     # row.append(ip_frag_offset)
            #     row.append(ip_ttl)
            #     row.append(ip_proto)
            #     row.append(ip_checksum)
            #     # row.append(ip_checksum_status)
            row["ip_src"] = ip_src
            #     row.append(ip_addr)
            #     row.append(ip_src_host)
            #     row.append(ip_host)
            row["ip_dst"] = ip_dst
        #     row.append(ip_dst_host)

        # Layer UDP
        if "UDP" in packet:
            #     udp_srcport = packet.udp.srcport
            #     udp_dstport = packet.udp.dstport
            #     udp_port = packet.udp.port
            #     udp_length = packet.udp.length
            #     udp_checksum = packet.udp.checksum
            #     udp_checksum_status = packet.udp.checksum_status
            #     udp_stream = packet.udp.stream
            udp_stream_pnum = packet.udp.stream_pnum
            #     udp_time_relative = packet.udp.time_relative
            #     udp_time_delta = packet.udp.time_delta
            # udp_payload = packet.udp.payload

            #     row.append(udp_srcport)
            #     row.append(udp_dstport)
            #     row.append(udp_port)
            #     row.append(udp_length)
            #     row.append(udp_checksum)
            #     row.append(udp_checksum_status)
            #     row.append(udp_stream)
            row["udp_stream_pnum"] = udp_stream_pnum
        #     row.append(udp_time_relative)
        #     row.append(udp_time_delta)
        #     row.append(udp_payload)

        # # Layer BVLC
        # if "BVLC" in packet:
        #     bvlc_type = packet.bvlc.type
        #     bvlc_function = packet.bvlc.function
        #     bvlc_length = packet.bvlc.length
        #     bvlc_fwd_ip = packet.bvlc.fwd_ip
        #     bvlc_fwd_port = packet.bvlc.fwd_port

        #     row.append(bvlc_type)
        #     row.append(bvlc_function)
        #     row.append(bvlc_length)
        #     row.append(bvlc_fwd_ip)
        #     row.append(bvlc_fwd_port)

        # # Layer BACNET
        # if "BACNET" in packet:
        #     bacnet_version = packet.bacnet.version
        #     bacnet_control = packet.bacnet.control
        #     bacnet_control_net = packet.bacnet.control_net
        #     bacnet_control_res1 = packet.bacnet.control_res1
        #     bacnet_control_dest = packet.bacnet.control_dest
        #     bacnet_control_res2 = packet.bacnet.control_res2
        #     bacnet_control_src = packet.bacnet.control_src
        #     bacnet_control_expect = packet.bacnet.control_expect
        #     bacnet_control_prio_high = packet.bacnet.control_prio_high
        #     bacnet_control_prio_low = packet.bacnet.control_prio_low
        #     bacnet_dnet = packet.bacnet.dnet
        #     bacnet_dlen = packet.bacnet.dlen
        #     bacnet_hopc = packet.bacnet.hopc

        #     row.append(bacnet_version)
        #     row.append(bacnet_control)
        #     row.append(bacnet_control_net)
        #     row.append(bacnet_control_res1)
        #     row.append(bacnet_control_dest)
        #     row.append(bacnet_control_res2)
        #     row.append(bacnet_control_src)
        #     row.append(bacnet_control_expect)
        #     row.append(bacnet_control_prio_high)
        #     row.append(bacnet_control_prio_low)
        #     row.append(bacnet_dnet)
        #     row.append(bacnet_dlen)
        #     row.append(bacnet_hopc)

        # # Layer BACAPP
        # if "BACAPP" in packet:
        # bacapp_type = packet.bacapp.type
        # bacapp_unconfirmed_service = packet.bacapp.unconfirmed_service
        # # bacapp_who_is_low_limit = packet.bacapp.who_is.low_limit
        # # "": "Context Tag: 0, Length/Value/Type: 2",
        # bacapp_tag_class = packet.bacapp.tag_class
        # bacapp_context_tag_number = packet.bacapp.context_tag_number
        # bacapp_LVT = packet.bacapp.LVT
        # # bacapp_who_is_high_limit = packet.bacapp.who_is.high_limit

        # row.append(bacapp_type)
        # row.append(bacapp_unconfirmed_service)
        # # row.append(bacapp_who_is_low_limit)
        # row.append(bacapp_tag_class)
        # row.append(bacapp_context_tag_number)
        # row.append(bacapp_LVT)
        # # row.append(bacapp_who_is_high_limit)

        pcap_rows[i] = row
    else:
        break

# print(pcap_rows)
packet_streams = {}

for k, row in pcap_rows.items():
    __src_mac = row["eth_src"]
    __dst_mac = row["eth_dst"]
    __src_ip = row["ip_src"]
    __dst_ip = row["ip_dst"]
    __usp = row["udp_stream_pnum"]

    if not __usp in packet_streams:
        packet_streams[__usp] = {
            "IPs": [],
            "MACs": [],
            "Packets": [],
            "USP": __usp
        }
    
    __stream = packet_streams[__usp]
    __stream["Packets"].append(row["packet"])
    
    # IP
    if not __src_ip in __stream["IPs"]:
        __stream["IPs"].append(__src_ip)
    if not __dst_ip in __stream["IPs"]:
        __stream["IPs"].append(__dst_ip)
    
    # Macs
    if not __src_mac in __stream["MACs"]:
        __stream["MACs"].append(__src_mac)
    if not __dst_mac in __stream["MACs"]:
        __stream["MACs"].append(__dst_mac)
   
# x = packet_streams["100"]
# print(x)

print(packet_streams)





















# EXTRACT OBJECT FIELD NAMES
# for field in dir(packet.bacapp):
#     if not field.startswith('__'):  # Skip special methods
#         try:
#             value = getattr(packet.bacapp, field)
#             print(f"{field}: {value}")
#         except AttributeError:
#             print(f"AttributeError accessing {field}")
