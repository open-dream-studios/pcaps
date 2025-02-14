import pyshark

frames = {}

for packet in pyshark.FileCapture("250203.pcapng"):
  sIndex                    = packet.udp.stream
  
  if not sIndex in frames:
    frames[sIndex] = {
      "eth"                : {},
      "ip"                 : {},
      "packets"            : [],
      "stream_index"       : sIndex,
      }
    
  _frame                    = frames[sIndex]
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
