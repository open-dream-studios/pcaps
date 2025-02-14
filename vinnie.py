import pyshark

packet_dir = [
  '_packet_string',
  'bacapp',
  'bacnet',
  'bvlc',
  'captured_length',
  'eth',
  'frame_info',
  'get_multiple_layers',
  'get_raw_packet',
  'highest_layer',
  'interface_captured',
  'ip',
  'layers',
  'length',
  'number',
  'pretty_print',
  'show',
  'sniff_time',
  'sniff_timestamp',
  'transport_layer',
  'udp']

packet_dict = {
  "layers" : [],
  "frame_info" : object,
  "number" : str,
  "interface_captured" : object,
  "captured_length" : str,
  "length" : str,
  "sniff_timestamp" : str
  }

_cap = pyshark.FileCapture("250203.pcapng")
frames = {}
_dir = {}

for i, packet in enumerate(_cap):
  sIndex                    = packet.udp.stream
  sNum                      = packet.udp.stream_pnum
  
  if not sIndex in frames:
    frames[packet.udp.stream] = {
      "eth"                : {},
      "ip"                 : {},
      "packets"            : [],
      "stream_index"       : packet.udp.stream,
      }
    
    _frame                    = frames[packet.udp.stream]
    
    _frame["packets"].append(packet)
    
    if not packet.eth.src in _frame["eth"]:
      _frame["eth"][packet.eth.src] = True
    if not packet.eth.dst in _frame["eth"]:
      _frame["eth"][packet.eth.dst] = True
      
    if not packet.ip.src in _frame["ip"]:
      _frame["ip"][packet.ip.src] = True
    if not packet.ip.dst in _frame["ip"]:
      _frame["ip"][packet.ip.dst] = True
 
 
 
print(frames["100"])
