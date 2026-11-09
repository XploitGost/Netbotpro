"""Per-socket libpcap byte-copy adapter; Scapy still decodes every frame."""
import ctypes
import os


class PcapByteReader:
    def __init__(self, original, next_packet=None):
        self.original = original
        if next_packet is None:
            from scapy.libs.winpcapy import pcap_next_ex
            next_packet = pcap_next_ex
        self.next_packet = next_packet
        self.wire_length = None
        self.closed = False

    def __getattr__(self, name):
        return getattr(self.original, name)

    def next(self):
        if self.closed:
            raise EOFError('Capture handle closed')
        fd = self.original
        status = self.next_packet(fd.pcap, ctypes.byref(fd.header), ctypes.byref(fd.pkt_data))
        if status <= 0:
            fd.remaining = False
            if status == -2:
                raise EOFError('Capture stream ended')
            if status < 0:
                raise OSError('pcap_next_ex failed')
            return None, None
        header = fd.header.contents
        length, wire_length = int(header.caplen), int(header.len)
        if length > wire_length or length > 16*1024*1024 or (length and not fd.pkt_data):
            raise ValueError('Invalid pcap frame lengths')
        fd.remaining = True
        self.wire_length = wire_length
        timestamp = header.ts.tv_sec + float(header.ts.tv_usec)/1e6
        # Copy exactly caplen: pointer slicing builds a Python integer list and
        # reading wirelen would exceed the available data on truncated captures.
        return timestamp, ctypes.string_at(fd.pkt_data, length) if length else b''

    __next__ = next

    def close(self):
        if not self.closed:
            self.closed = True
            self.original.close()


class CaptureSocket:
    _netbot_fast_copy = True

    def __init__(self, original):
        self.original = original

    def __getattr__(self, name):
        return getattr(self.original, name)

    def recv(self, *args, **kwargs):
        packet = self.original.recv(*args, **kwargs)
        if packet is not None:
            packet.wirelen = self.original.pcap_fd.wire_length
        return packet


def attach_fast_reader(socket):
    if os.environ.get('NETBOT_FAST_PCAP_COPY', '1') == '0':
        return socket
    fd = getattr(socket, 'pcap_fd', None)
    if fd is None or not all(hasattr(fd, key) for key in ('pcap', 'header', 'pkt_data', 'remaining')):
        return socket
    socket.pcap_fd = PcapByteReader(fd)
    if getattr(socket, '_netbot_buffer_bytes', None) is not None and os.environ.get('NETBOT_RAW_PREFETCH', '1') != '0':
        from .raw_buffer import RawBuffer, BufferedSocket
        reader = RawBuffer(socket.pcap_fd)
        socket.pcap_fd = reader
        return BufferedSocket(socket, reader)
    return CaptureSocket(socket)
