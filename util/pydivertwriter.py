from scapy.utils import PcapWriter as _PcapWriter
from scapy.layers.inet import IP as _IP


class PydivertWriter(_PcapWriter):
    def write(self, packet):
        scapy_packet = _IP(bytes(packet.raw))
        super().write(scapy_packet)
