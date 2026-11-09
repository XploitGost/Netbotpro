from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from core.netbotpro_sniffer_core.pcap_config import create_handle, requested_buffer_size


class PcapConfigurationTests(unittest.TestCase):
    def api(self):
        api = Mock()
        api.PCAP_ERRBUF_SIZE = 256
        api.pcap_create.return_value = 'owned-handle'
        for method in ('pcap_set_snaplen', 'pcap_set_promisc', 'pcap_set_timeout', 'pcap_set_buffer_size', 'pcap_activate'):
            getattr(api, method).return_value = 0
        return api

    def test_buffer_is_set_before_activation_and_never_reconfigured_live(self):
        api = self.api()
        handle, _error, status = create_handle('test', 65535, True, 8*1024*1024, api)
        self.assertEqual(handle, 'owned-handle')
        self.assertEqual(status, 0)
        names = [call[0] for call in api.mock_calls]
        self.assertLess(names.index('pcap_set_buffer_size'), names.index('pcap_activate'))
        api.pcap_setbuff.assert_not_called()
        api.pcap_close.assert_not_called()

    def test_configuration_failure_closes_handle_without_activation(self):
        api = self.api()
        api.pcap_set_buffer_size.return_value = -1
        with self.assertRaises(OSError):
            create_handle('test', 65535, True, 8*1024*1024, api)
        api.pcap_close.assert_called_once_with('owned-handle')
        api.pcap_activate.assert_not_called()

    def test_activation_failure_and_positive_warning(self):
        api = self.api()
        api.pcap_activate.return_value = -1
        with self.assertRaises(OSError):
            create_handle('test', 65535, True, 8*1024*1024, api)
        api.pcap_close.assert_called_once()
        api = self.api()
        api.pcap_activate.return_value = 2
        self.assertEqual(create_handle('test', 65535, True, 8*1024*1024, api)[2], 2)

    def test_memory_request_is_bounded(self):
        for value, expected in (('-1', 1*1024*1024), ('9999999999', 16*1024*1024), ('invalid', 8*1024*1024)):
            with patch.dict('os.environ', NETBOT_PCAP_BUFFER_BYTES=value):
                self.assertEqual(requested_buffer_size(), expected)
