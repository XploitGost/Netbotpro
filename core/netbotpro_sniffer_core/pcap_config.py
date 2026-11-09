"""Configure an owned Npcap handle before activation; reuse Scapy's I/O/decoder."""
import ctypes
import os


def requested_buffer_size():
    try:
        value = int(os.environ.get('NETBOT_PCAP_BUFFER_BYTES', str(8*1024*1024)))
    except ValueError:
        value = 8*1024*1024
    return max(1024*1024, min(16*1024*1024, value))


def create_handle(device, snaplen, promisc, buffer_bytes, api):
    error = ctypes.create_string_buffer(api.PCAP_ERRBUF_SIZE)
    handle = api.pcap_create(device.encode('utf-8'), error)
    if not handle:
        raise OSError('pcap_create failed')
    try:
        for function, value in (
            (api.pcap_set_snaplen, snaplen), (api.pcap_set_promisc, int(bool(promisc))),
            (api.pcap_set_timeout, 100), (api.pcap_set_buffer_size, buffer_bytes),
        ):
            if function(handle, value) != 0:
                raise OSError('Npcap pre-activation configuration failed')
        status = api.pcap_activate(handle)
        if status < 0:
            raise OSError('Npcap activation failed')
        return handle, error, status
    except BaseException:
        api.pcap_close(handle)
        raise


def open_configured_socket(device, capture_filter):
    from scapy.config import conf
    if os.name != 'nt' or not conf.use_npcap:
        return None
    from scapy.arch.libpcap import _PcapWrapper_libpcap, _L2libpcapSocket, L2pcapListenSocket
    from scapy.data import ETH_P_ALL, MTU
    from scapy.interfaces import resolve_iface
    from scapy.libs import winpcapy as api

    class OwnedDescriptor(_PcapWrapper_libpcap):
        def close(self):
            if not self._owned_closed:
                self._owned_closed = True
                super().close()

    resolved = resolve_iface(device).network_name
    size = requested_buffer_size()
    handle, error, warning = create_handle(resolved, MTU, conf.sniff_promisc, size, api)
    fd = socket = None
    descriptor_ready = False
    try:
        fd = OwnedDescriptor.__new__(OwnedDescriptor)
        fd._owned_closed = False
        fd.pcap = handle
        descriptor_ready = True
        fd.errbuf = error
        fd.iface = ctypes.create_string_buffer(resolved.encode('utf-8'))
        fd.dtl = -1
        fd.remaining = True
        api.pcap_setmintocopy(handle, 0)
        fd.header = ctypes.POINTER(api.pcap_pkthdr)()
        fd.pkt_data = ctypes.POINTER(ctypes.c_ubyte)()
        fd.bpf_program = api.bpf_program()
        socket = L2pcapListenSocket.__new__(L2pcapListenSocket)
        socket.iface, socket.type, socket.outs = resolved, ETH_P_ALL, None
        socket.promisc, socket.monitor = conf.sniff_promisc, None
        _L2libpcapSocket.__init__(socket, fd)
        if conf.except_filter:
            capture_filter = '(' + capture_filter + ') and not (' + conf.except_filter + ')' if capture_filter else 'not (' + conf.except_filter + ')'
        if capture_filter:
            fd.setfilter(capture_filter)
        socket._netbot_buffer_bytes = size
        socket._netbot_activation_warning = warning
        return socket
    except BaseException:
        if socket is not None:
            socket.closed = True
        if descriptor_ready:
            fd.close()
        else:
            api.pcap_close(handle)
        raise
