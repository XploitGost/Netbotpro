import asyncio
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.app.repositories.history_repository import AlertListQuery, MemoryHistoryRepository, PacketListQuery, SQLiteHistoryRepository


class _FakeSnifferService:
    def recent_packets(self):
        return [
            {"id": "mem-pkt-2", "src": "10.0.0.2", "dst": "8.8.8.8", "proto": "UDP", "summary": "two", "remote_ip": "8.8.8.8", "app_protocol": "DNS", "dns_qname": "api.example.com"},
            {"id": "mem-pkt-1", "src": "10.0.0.1", "dst": "1.1.1.1", "proto": "TCP", "summary": "one", "remote_ip": "1.1.1.1", "app_protocol": "HTTPS", "sni": "example.com"},
        ]

    def recent_alerts(self):
        return [
            {"id": "mem-alert-2", "src": "8.8.8.8", "dst": "10.0.0.2", "attack_type": "Burst", "score": 1.0, "detail": "two", "remote_ip": "8.8.8.8", "app_protocol": "DNS"},
            {"id": "mem-alert-1", "src": "1.1.1.1", "dst": "10.0.0.1", "attack_type": "Scan", "score": 0.5, "detail": "one", "remote_ip": "1.1.1.1", "app_protocol": "HTTPS"},
        ]


class _FlowSnifferService:
    def recent_packets(self):
        return [
            {"id": "mem-pkt-4", "ts": "10:00:07", "src": "192.168.1.10", "dst": "8.8.8.8", "proto": "TCP", "sport": 55001, "dport": 80, "length": 90, "summary": "other-port", "remote_ip": "8.8.8.8", "direction": "OUTGOING"},
            {"id": "mem-pkt-3", "ts": "10:00:06", "src": "8.8.8.8", "dst": "192.168.1.10", "proto": "TCP", "sport": 443, "dport": 55000, "length": 220, "summary": "response", "remote_ip": "8.8.8.8", "direction": "INCOMING"},
            {"id": "mem-pkt-2", "ts": "10:00:05", "src": "192.168.1.10", "dst": "8.8.8.8", "proto": "TCP", "sport": 55000, "dport": 443, "length": 150, "summary": "request-2", "remote_ip": "8.8.8.8", "direction": "OUTGOING"},
            {"id": "mem-pkt-1", "ts": "10:00:04", "src": "192.168.1.10", "dst": "8.8.8.8", "proto": "TCP", "sport": 55000, "dport": 443, "length": 120, "summary": "request-1", "remote_ip": "8.8.8.8", "direction": "OUTGOING"},
        ]

    def recent_alerts(self):
        return [
            {"id": "mem-alert-1", "ts": "10:00:06", "src": "8.8.8.8", "dst": "192.168.1.10", "proto": "TCP", "attack_type": "Interesting", "score": 0.8, "detail": "same flow", "packet_id": "mem-pkt-3", "remote_ip": "8.8.8.8"},
        ]


class _BehaviorSnifferService:
    def recent_packets(self):
        return [
            {"id": "mem-behavior-7", "ts": "10:00:07", "src": "192.168.1.10", "dst": "8.8.8.8", "proto": "TCP", "sport": 55005, "dport": 443, "length": 96, "summary": "repeat-peer", "remote_ip": "8.8.8.8", "direction": "OUTGOING", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "mem-behavior-6", "ts": "10:00:06", "src": "192.168.1.10", "dst": "4.4.4.4", "proto": "TCP", "sport": 55004, "dport": 8443, "length": 92, "summary": "alt-service", "remote_ip": "4.4.4.4", "direction": "OUTGOING", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "mem-behavior-5", "ts": "10:00:05", "src": "192.168.1.10", "dst": "8.8.4.4", "proto": "TCP", "sport": 55003, "dport": 443, "length": 88, "summary": "fanout-3", "remote_ip": "8.8.4.4", "direction": "OUTGOING", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "mem-behavior-4", "ts": "10:00:04", "src": "192.168.1.10", "dst": "9.9.9.9", "proto": "TCP", "sport": 55002, "dport": 443, "length": 86, "summary": "fanout-2", "remote_ip": "9.9.9.9", "direction": "OUTGOING", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "mem-behavior-3", "ts": "10:00:03", "src": "192.168.1.10", "dst": "1.1.1.1", "proto": "TCP", "sport": 55001, "dport": 443, "length": 84, "summary": "fanout-1", "remote_ip": "1.1.1.1", "direction": "OUTGOING", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "mem-behavior-2", "ts": "10:00:02", "src": "8.8.8.8", "dst": "192.168.1.10", "proto": "TCP", "sport": 443, "dport": 55000, "length": 140, "summary": "selected-response", "remote_ip": "8.8.8.8", "direction": "INCOMING"},
            {"id": "mem-behavior-1", "ts": "10:00:01", "src": "192.168.1.10", "dst": "8.8.8.8", "proto": "TCP", "sport": 55000, "dport": 443, "length": 110, "summary": "selected-request", "remote_ip": "8.8.8.8", "direction": "OUTGOING", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
        ]

    def recent_alerts(self):
        return []


class _BeaconBehaviorSnifferService:
    def recent_packets(self):
        return [
            {"id": "beacon-8", "ts": "10:00:46", "src": "203.0.113.10", "dst": "192.168.1.50", "proto": "TCP", "sport": 443, "dport": 51003, "length": 72, "summary": "beacon-4-resp", "remote_ip": "203.0.113.10", "direction": "INCOMING", "process_name": "agent.exe", "pid": 7711, "parent_pid": 7000, "parent_process_name": "services.exe", "executable_path": "C:/Program Files/Agent/agent.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "beacon-7", "ts": "10:00:45", "src": "192.168.1.50", "dst": "203.0.113.10", "proto": "TCP", "sport": 51003, "dport": 443, "length": 68, "summary": "beacon-4-req", "remote_ip": "203.0.113.10", "direction": "OUTGOING", "process_name": "agent.exe", "pid": 7711, "parent_pid": 7000, "parent_process_name": "services.exe", "executable_path": "C:/Program Files/Agent/agent.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "beacon-6", "ts": "10:00:31", "src": "203.0.113.10", "dst": "192.168.1.50", "proto": "TCP", "sport": 443, "dport": 51002, "length": 72, "summary": "beacon-3-resp", "remote_ip": "203.0.113.10", "direction": "INCOMING", "process_name": "agent.exe", "pid": 7711, "parent_pid": 7000, "parent_process_name": "services.exe", "executable_path": "C:/Program Files/Agent/agent.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "beacon-5", "ts": "10:00:30", "src": "192.168.1.50", "dst": "203.0.113.10", "proto": "TCP", "sport": 51002, "dport": 443, "length": 68, "summary": "beacon-3-req", "remote_ip": "203.0.113.10", "direction": "OUTGOING", "process_name": "agent.exe", "pid": 7711, "parent_pid": 7000, "parent_process_name": "services.exe", "executable_path": "C:/Program Files/Agent/agent.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "beacon-4", "ts": "10:00:16", "src": "203.0.113.10", "dst": "192.168.1.50", "proto": "TCP", "sport": 443, "dport": 51001, "length": 72, "summary": "beacon-2-resp", "remote_ip": "203.0.113.10", "direction": "INCOMING", "process_name": "agent.exe", "pid": 7711, "parent_pid": 7000, "parent_process_name": "services.exe", "executable_path": "C:/Program Files/Agent/agent.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "beacon-3", "ts": "10:00:15", "src": "192.168.1.50", "dst": "203.0.113.10", "proto": "TCP", "sport": 51001, "dport": 443, "length": 68, "summary": "beacon-2-req", "remote_ip": "203.0.113.10", "direction": "OUTGOING", "process_name": "agent.exe", "pid": 7711, "parent_pid": 7000, "parent_process_name": "services.exe", "executable_path": "C:/Program Files/Agent/agent.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "beacon-2", "ts": "10:00:01", "src": "203.0.113.10", "dst": "192.168.1.50", "proto": "TCP", "sport": 443, "dport": 51000, "length": 72, "summary": "beacon-1-resp", "remote_ip": "203.0.113.10", "direction": "INCOMING", "process_name": "agent.exe", "pid": 7711, "parent_pid": 7000, "parent_process_name": "services.exe", "executable_path": "C:/Program Files/Agent/agent.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "beacon-1", "ts": "10:00:00", "src": "192.168.1.50", "dst": "203.0.113.10", "proto": "TCP", "sport": 51000, "dport": 443, "length": 68, "summary": "beacon-1-req", "remote_ip": "203.0.113.10", "direction": "OUTGOING", "process_name": "agent.exe", "pid": 7711, "parent_pid": 7000, "parent_process_name": "services.exe", "executable_path": "C:/Program Files/Agent/agent.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
        ]

    def recent_alerts(self):
        return [
            {"id": "beacon-alert-1", "ts": "10:00:45", "src": "192.168.1.50", "dst": "203.0.113.10", "proto": "TCP", "attack_type": "Suspicious Recurrence", "score": 0.66, "detail": "linked beacon alert", "severity": "MEDIUM", "engine": "RULE", "packet_id": "beacon-7", "remote_ip": "203.0.113.10", "process_name": "agent.exe", "pid": 7711},
        ]


class _PortScanSnifferService:
    def recent_packets(self):
        return [
            {"id": "scan-6", "ts": "10:00:05", "src": "192.168.1.60", "dst": "198.51.100.30", "proto": "TCP", "sport": 52005, "dport": 3389, "length": 60, "summary": "scan-3389", "remote_ip": "198.51.100.30", "direction": "OUTGOING", "process_name": "scanner.exe", "pid": 8800, "parent_pid": 4000, "parent_process_name": "cmd.exe", "executable_path": "C:/Tools/scanner.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "scan-5", "ts": "10:00:04", "src": "192.168.1.60", "dst": "198.51.100.30", "proto": "TCP", "sport": 52004, "dport": 8443, "length": 60, "summary": "scan-8443", "remote_ip": "198.51.100.30", "direction": "OUTGOING", "process_name": "scanner.exe", "pid": 8800, "parent_pid": 4000, "parent_process_name": "cmd.exe", "executable_path": "C:/Tools/scanner.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "scan-4", "ts": "10:00:03", "src": "192.168.1.60", "dst": "198.51.100.30", "proto": "TCP", "sport": 52003, "dport": 443, "length": 60, "summary": "scan-443", "remote_ip": "198.51.100.30", "direction": "OUTGOING", "process_name": "scanner.exe", "pid": 8800, "parent_pid": 4000, "parent_process_name": "cmd.exe", "executable_path": "C:/Tools/scanner.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "scan-3", "ts": "10:00:02", "src": "192.168.1.60", "dst": "198.51.100.30", "proto": "TCP", "sport": 52002, "dport": 80, "length": 60, "summary": "scan-80", "remote_ip": "198.51.100.30", "direction": "OUTGOING", "process_name": "scanner.exe", "pid": 8800, "parent_pid": 4000, "parent_process_name": "cmd.exe", "executable_path": "C:/Tools/scanner.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "scan-2", "ts": "10:00:01", "src": "192.168.1.60", "dst": "198.51.100.30", "proto": "TCP", "sport": 52001, "dport": 23, "length": 60, "summary": "scan-23", "remote_ip": "198.51.100.30", "direction": "OUTGOING", "process_name": "scanner.exe", "pid": 8800, "parent_pid": 4000, "parent_process_name": "cmd.exe", "executable_path": "C:/Tools/scanner.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
            {"id": "scan-1", "ts": "10:00:00", "src": "192.168.1.60", "dst": "198.51.100.30", "proto": "TCP", "sport": 52000, "dport": 22, "length": 60, "summary": "scan-22", "remote_ip": "198.51.100.30", "direction": "OUTGOING", "process_name": "scanner.exe", "pid": 8800, "parent_pid": 4000, "parent_process_name": "cmd.exe", "executable_path": "C:/Tools/scanner.exe", "attribution_confidence": "high", "attribution_source": "psutil"},
        ]

    def recent_alerts(self):
        return []


class _HttpStreamSnifferService:
    def recent_packets(self):
        return [
            {"id": "stream-4", "ts": "10:00:03", "src": "93.184.216.34", "dst": "192.168.1.70", "proto": "TCP", "sport": 443, "dport": 53000, "length": 220, "summary": "http-response", "remote_ip": "93.184.216.34", "direction": "INCOMING", "app_protocol": "HTTP", "http_status": 200, "http_reason": "OK", "http_content_type": "application/json", "payload_ascii": "HTTP/1.1 200 OK {\"ok\":true}", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high"},
            {"id": "stream-3", "ts": "10:00:02", "src": "192.168.1.70", "dst": "93.184.216.34", "proto": "TCP", "sport": 53000, "dport": 443, "length": 120, "summary": "http-request-body", "remote_ip": "93.184.216.34", "direction": "OUTGOING", "app_protocol": "HTTP", "payload_ascii": "authorization=token&state=ready", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high"},
            {"id": "stream-2", "ts": "10:00:01", "src": "192.168.1.70", "dst": "93.184.216.34", "proto": "TCP", "sport": 53000, "dport": 443, "length": 140, "summary": "http-request", "remote_ip": "93.184.216.34", "direction": "OUTGOING", "app_protocol": "HTTP", "http_method": "POST", "http_host": "example.com", "http_path": "/login", "payload_ascii": "POST /login HTTP/1.1 Host: example.com", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high"},
            {"id": "stream-1", "ts": "10:00:00", "src": "192.168.1.70", "dst": "93.184.216.34", "proto": "TCP", "sport": 53000, "dport": 443, "length": 90, "summary": "tcp-setup", "remote_ip": "93.184.216.34", "direction": "OUTGOING", "process_name": "browser.exe", "pid": 4242, "parent_pid": 4000, "parent_process_name": "explorer.exe", "executable_path": "C:/Program Files/Browser/browser.exe", "attribution_confidence": "high"},
        ]

    def recent_alerts(self):
        return [
            {"id": "stream-alert-2", "ts": "10:00:03", "src": "93.184.216.34", "dst": "192.168.1.70", "proto": "TCP", "sport": 443, "dport": 53000, "direction": "INCOMING", "attack_type": "HTTP Response Flag", "score": 0.58, "detail": "Response completed on monitored stream", "severity": "MEDIUM", "engine": "RULE", "packet_id": "stream-4", "remote_ip": "93.184.216.34", "process_name": "browser.exe", "pid": 4242},
            {"id": "stream-alert-1", "ts": "10:00:02", "src": "192.168.1.70", "dst": "93.184.216.34", "proto": "TCP", "sport": 53000, "dport": 443, "direction": "OUTGOING", "attack_type": "Credential POST", "score": 0.72, "detail": "POST body contained login material", "severity": "HIGH", "engine": "RULE", "packet_id": "stream-3", "remote_ip": "93.184.216.34", "process_name": "browser.exe", "pid": 4242},
        ]


class _PartialStreamSnifferService:
    def recent_packets(self):
        return [
            {"id": "partial-2", "ts": "10:00:01", "src": "203.0.113.77", "dst": "192.168.1.80", "proto": "TCP", "sport": 9000, "dport": 54000, "length": 88, "summary": "tcp-reply", "remote_ip": "203.0.113.77", "direction": "INCOMING", "payload_ascii": "HELLO ACK"},
            {"id": "partial-1", "ts": "10:00:00", "src": "192.168.1.80", "dst": "203.0.113.77", "proto": "TCP", "sport": 54000, "dport": 9000, "length": 84, "summary": "tcp-request", "remote_ip": "203.0.113.77", "direction": "OUTGOING", "payload_ascii": "HELLO SYN"},
        ]

    def recent_alerts(self):
        return []


class _ConversationDiffSnifferService:
    def recent_packets(self):
        return [
            {"id": "diff-6", "ts": "10:01:05", "src": "93.184.216.34", "dst": "192.168.1.90", "proto": "TCP", "sport": 443, "dport": 54000, "length": 210, "summary": "http-response-2", "remote_ip": "93.184.216.34", "direction": "INCOMING", "app_protocol": "HTTP", "http_status": 403, "http_reason": "Forbidden", "http_content_type": "text/html", "payload_ascii": "HTTP/1.1 403 Forbidden", "process_name": "browser.exe", "pid": 5001},
            {"id": "diff-5", "ts": "10:01:04", "src": "192.168.1.90", "dst": "93.184.216.34", "proto": "TCP", "sport": 54000, "dport": 443, "length": 130, "summary": "http-request-2-body", "remote_ip": "93.184.216.34", "direction": "OUTGOING", "app_protocol": "HTTP", "payload_ascii": "admin=true", "process_name": "browser.exe", "pid": 5001},
            {"id": "diff-4", "ts": "10:01:03", "src": "192.168.1.90", "dst": "93.184.216.34", "proto": "TCP", "sport": 54000, "dport": 443, "length": 140, "summary": "http-request-2", "remote_ip": "93.184.216.34", "direction": "OUTGOING", "app_protocol": "HTTP", "http_method": "GET", "http_host": "example.com", "http_path": "/admin", "payload_ascii": "GET /admin HTTP/1.1 Host: example.com", "process_name": "browser.exe", "pid": 5001},
            {"id": "diff-3", "ts": "10:01:02", "src": "93.184.216.34", "dst": "192.168.1.90", "proto": "TCP", "sport": 443, "dport": 54000, "length": 220, "summary": "http-response-1", "remote_ip": "93.184.216.34", "direction": "INCOMING", "app_protocol": "HTTP", "http_status": 200, "http_reason": "OK", "http_content_type": "application/json", "payload_ascii": "HTTP/1.1 200 OK", "process_name": "browser.exe", "pid": 5001},
            {"id": "diff-2", "ts": "10:01:01", "src": "192.168.1.90", "dst": "93.184.216.34", "proto": "TCP", "sport": 54000, "dport": 443, "length": 120, "summary": "http-request-1-body", "remote_ip": "93.184.216.34", "direction": "OUTGOING", "app_protocol": "HTTP", "payload_ascii": "username=admin", "process_name": "browser.exe", "pid": 5001},
            {"id": "diff-1", "ts": "10:01:00", "src": "192.168.1.90", "dst": "93.184.216.34", "proto": "TCP", "sport": 54000, "dport": 443, "length": 145, "summary": "http-request-1", "remote_ip": "93.184.216.34", "direction": "OUTGOING", "app_protocol": "HTTP", "http_method": "POST", "http_host": "example.com", "http_path": "/login", "payload_ascii": "POST /login HTTP/1.1 Host: example.com", "process_name": "browser.exe", "pid": 5001},
        ]

    def recent_alerts(self):
        return []


class _AlertCorrelationSnifferService:
    def recent_packets(self):
        return [
            {
                "id": "mem-pkt-3",
                "capture_id": "cap-3",
                "ts": "10:00:07",
                "src": "192.168.1.10",
                "dst": "8.8.8.8",
                "proto": "TCP",
                "sport": 55001,
                "dport": 443,
                "length": 96,
                "summary": "same-remote",
                "remote_ip": "8.8.8.8",
                "direction": "OUTGOING",
                "process_name": "browser.exe",
                "pid": 4242,
                "parent_pid": 4000,
                "parent_process_name": "explorer.exe",
                "executable_path": "C:/Program Files/Browser/browser.exe",
                "attribution_confidence": "high",
                "attribution_source": "psutil",
            },
            {
                "id": "mem-pkt-2",
                "capture_id": "cap-2",
                "ts": "10:00:06",
                "src": "8.8.8.8",
                "dst": "192.168.1.10",
                "proto": "TCP",
                "sport": 443,
                "dport": 55000,
                "length": 220,
                "summary": "selected-response",
                "remote_ip": "8.8.8.8",
                "direction": "INCOMING",
                "process_name": "browser.exe",
                "pid": 4242,
                "parent_pid": 4000,
                "parent_process_name": "explorer.exe",
                "executable_path": "C:/Program Files/Browser/browser.exe",
                "attribution_confidence": "high",
                "attribution_source": "psutil",
            },
            {
                "id": "mem-pkt-1",
                "capture_id": "cap-1",
                "ts": "10:00:05",
                "src": "192.168.1.10",
                "dst": "8.8.8.8",
                "proto": "TCP",
                "sport": 55000,
                "dport": 443,
                "length": 120,
                "summary": "selected-request",
                "remote_ip": "8.8.8.8",
                "direction": "OUTGOING",
                "process_name": "browser.exe",
                "pid": 4242,
                "parent_pid": 4000,
                "parent_process_name": "explorer.exe",
                "executable_path": "C:/Program Files/Browser/browser.exe",
                "attribution_confidence": "high",
                "attribution_source": "psutil",
            },
        ]

    def recent_alerts(self):
        return [
            {
                "id": "mem-alert-2",
                "ts": "10:00:07",
                "src": "8.8.8.8",
                "dst": "192.168.1.10",
                "proto": "TCP",
                "sport": 443,
                "dport": 55001,
                "direction": "INCOMING",
                "attack_type": "Remote Recurrence",
                "score": 0.6,
                "detail": "same remote different flow",
                "severity": "MEDIUM",
                "engine": "RULE",
                "packet_id": "cap-3",
                "remote_ip": "8.8.8.8",
                "process_name": "browser.exe",
                "pid": 4242,
            },
            {
                "id": "mem-alert-1",
                "ts": "10:00:06",
                "src": "8.8.8.8",
                "dst": "192.168.1.10",
                "proto": "TCP",
                "sport": 443,
                "dport": 55000,
                "direction": "INCOMING",
                "attack_type": "Suspicious Tunnel",
                "score": 0.9,
                "detail": "linked packet alert",
                "severity": "HIGH",
                "engine": "RULE",
                "packet_id": "cap-2",
                "remote_ip": "8.8.8.8",
                "process_name": "browser.exe",
                "pid": 4242,
            },
        ]


class MemoryHistoryRepositoryTests(unittest.TestCase):
    def test_memory_detail_lookup_uses_stable_packet_id(self):
        repository = MemoryHistoryRepository(_FakeSnifferService())

        packet = repository.get_packet_detail("mem-pkt-1")

        self.assertIsNotNone(packet)
        self.assertEqual(packet["src"], "10.0.0.1")

    def test_memory_detail_lookup_uses_stable_alert_id(self):
        repository = MemoryHistoryRepository(_FakeSnifferService())

        alert = repository.get_alert_detail("mem-alert-2")

        self.assertIsNotNone(alert)
        self.assertEqual(alert["attack_type"], "Burst")

    def test_only_remote_filter_keeps_external_flows(self):
        repository = MemoryHistoryRepository(_FakeSnifferService())

        result = repository.list_packets(PacketListQuery(only_remote=True))

        self.assertEqual(result["total"], 2)
        self.assertEqual(result["items"][0]["dst"], "8.8.8.8")

    def test_remote_filter_ignores_stale_local_remote_ip_when_public_peer_exists(self):
        class _StaleRemoteSniffer:
            def recent_packets(self):
                return [
                    {"id": "mem-pkt-x", "src": "192.168.1.10", "dst": "8.8.8.8", "proto": "TCP", "summary": "public", "remote_ip": "192.168.1.1"},
                ]

            def recent_alerts(self):
                return []

        repository = MemoryHistoryRepository(_StaleRemoteSniffer())

        result = repository.list_packets(PacketListQuery(only_remote=True))

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["dst"], "8.8.8.8")

    def test_memory_packet_flow_context_tracks_session_stats(self):
        repository = MemoryHistoryRepository(_FlowSnifferService())

        context = repository.get_packet_flow_context("mem-pkt-3")

        self.assertIsNotNone(context)
        self.assertTrue(str(context["flow_id"]).startswith("flow-"))
        self.assertEqual(context["flow_packets_total"], 3)
        self.assertEqual(context["flow_bytes_in"], 220)
        self.assertEqual(context["flow_bytes_out"], 270)
        self.assertEqual(context["same_peer_packets_total"], 4)
        self.assertEqual(context["same_port_packets_total"], 3)
        self.assertEqual(context["flow_alerts_total"], 1)
        self.assertEqual(context["first_seen"], "10:00:04")
        self.assertEqual(context["last_seen"], "10:00:06")
        self.assertEqual(len(context["related_packets"]), 2)
        self.assertEqual(context["related_packets"][0]["id"], "mem-pkt-2")

    def test_memory_packet_flow_context_exposes_behavior_correlation(self):
        repository = MemoryHistoryRepository(_BehaviorSnifferService())

        context = repository.get_packet_flow_context("mem-behavior-1")

        self.assertIsNotNone(context)
        self.assertEqual(context["sample_packets"], 7)
        self.assertIn("Fan-out pattern observed", context["behavior_labels"])
        self.assertIn("Sweep pattern candidate", context["behavior_labels"])
        self.assertEqual(context["process_correlation"]["pattern"], "Multi-port multi-host process activity")
        self.assertEqual(context["host_correlation"]["remote_hosts_total"], 5)
        self.assertEqual(context["host_correlation"]["selected_remote_sessions_total"], 2)
        self.assertEqual(context["port_correlation"]["pattern"], "Sweep pattern candidate")
        self.assertEqual(context["port_correlation"]["remote_port_remote_hosts_total"], 4)
        self.assertTrue(context["conversation_clusters"])
        self.assertEqual(context["conversation_clusters"][0]["title"], "8.8.8.8 (TCP)")
        self.assertEqual(context["process_correlation"]["parent_process_name"], "explorer.exe")
        self.assertEqual(context["process_correlation"]["executable_path"], "C:/Program Files/Browser/browser.exe")
        self.assertEqual(context["process_correlation"]["attribution_confidence"], "high")
        self.assertTrue(any(item["label"] == "Fan-out pattern observed" for item in context["behavior_evidence"]))

    def test_memory_alert_context_links_packet_flow_and_process(self):
        repository = MemoryHistoryRepository(_AlertCorrelationSnifferService())

        context = repository.get_alert_context("mem-alert-1")

        self.assertIsNotNone(context)
        self.assertEqual(context["packet_id"], "cap-2")
        self.assertEqual(context["linked_packet_id"], "mem-pkt-2")
        self.assertEqual(context["process_correlation"]["label"], "browser.exe")
        self.assertEqual(context["alert_correlation"]["peer_alerts_total"], 2)
        self.assertEqual(len(context["same_remote_alerts"]), 1)
        self.assertEqual(len(context["related_flows"]), 1)
        self.assertTrue(any(group["title"] == "Packet to Alert Chain" for group in context["root_cause_groups"]))

    def test_memory_packet_flow_context_detects_beacon_like_repetition(self):
        repository = MemoryHistoryRepository(_BeaconBehaviorSnifferService())

        context = repository.get_packet_flow_context("beacon-7")

        self.assertIsNotNone(context)
        self.assertIn("Repeated short connections observed", context["behavior_labels"])
        self.assertIn("Beacon-like repetition observed", context["behavior_labels"])
        self.assertTrue(any(item["id"] == "beacon_like_repetition" for item in context["behavior_evidence"]))
        self.assertEqual(context["process_correlation"]["label"], "agent.exe")

    def test_memory_alert_context_keeps_behavior_evidence(self):
        repository = MemoryHistoryRepository(_BeaconBehaviorSnifferService())

        context = repository.get_alert_context("beacon-alert-1")

        self.assertIsNotNone(context)
        self.assertIn("Beacon-like repetition observed", context["behavior_labels"])
        self.assertTrue(any(item["scope"] == "flow" for item in context["behavior_evidence"]))

    def test_memory_packet_flow_context_detects_simple_port_scan_candidate(self):
        repository = MemoryHistoryRepository(_PortScanSnifferService())

        context = repository.get_packet_flow_context("scan-6")

        self.assertIsNotNone(context)
        self.assertIn("Simple port-scan candidate", context["behavior_labels"])
        self.assertEqual(context["port_correlation"]["pattern"], "Simple port-scan candidate")
        self.assertEqual(context["port_correlation"]["same_remote_target_ports_total"], 6)

    def test_memory_packet_flow_context_reconstructs_http_stream_summary(self):
        repository = MemoryHistoryRepository(_HttpStreamSnifferService())

        context = repository.get_packet_flow_context("stream-4")

        self.assertIsNotNone(context)
        self.assertEqual(context["stream_context"]["status"], "complete")
        self.assertEqual(context["stream_context"]["protocol"], "HTTP")
        self.assertEqual(context["stream_context"]["requests_total"], 1)
        self.assertEqual(context["stream_context"]["responses_total"], 1)
        self.assertEqual(context["stream_context"]["pairs_total"], 1)
        self.assertEqual(context["stream_context"]["request_response_pairs"][0]["request_title"], "POST /login")
        self.assertEqual(context["stream_context"]["request_response_pairs"][0]["response_title"], "200 OK")
        self.assertEqual(context["stream_context"]["payload_snippets_total"], 1)

    def test_memory_packet_flow_context_includes_stream_timeline_navigation_and_processes(self):
        repository = MemoryHistoryRepository(_HttpStreamSnifferService())

        context = repository.get_packet_flow_context("stream-3")

        self.assertIsNotNone(context)
        self.assertEqual(context["stream_context"]["timeline_total"], 6)
        self.assertEqual(context["stream_context"]["stream_packets_total"], 4)
        self.assertEqual(context["stream_context"]["stream_alerts_total"], 2)
        self.assertEqual(context["stream_context"]["stream_processes_total"], 1)
        self.assertEqual(context["stream_context"]["navigation"]["previous_packet_id"], "stream-2")
        self.assertEqual(context["stream_context"]["navigation"]["next_packet_id"], "stream-4")
        self.assertEqual(context["stream_context"]["processes"][0]["label"], "browser.exe")
        self.assertTrue(any(item["kind"] == "alert" for item in context["stream_context"]["timeline"]))

    def test_memory_alert_context_includes_same_stream_navigation(self):
        repository = MemoryHistoryRepository(_HttpStreamSnifferService())

        context = repository.get_alert_context("stream-alert-1")

        self.assertIsNotNone(context)
        self.assertEqual(context["stream_context"]["navigation"]["current_alert_id"], "stream-alert-1")
        self.assertEqual(context["stream_context"]["navigation"]["next_alert_id"], "stream-alert-2")
        self.assertEqual(context["stream_context"]["navigation"]["previous_alert_id"], None)
        self.assertEqual(context["stream_context"]["navigation"]["current_packet_id"], "stream-3")
        self.assertTrue(any(item["is_current"] for item in context["stream_context"]["timeline"] if item["kind"] == "alert"))

    def test_memory_packet_flow_context_falls_back_to_payload_snippets(self):
        repository = MemoryHistoryRepository(_PartialStreamSnifferService())

        context = repository.get_packet_flow_context("partial-1")

        self.assertIsNotNone(context)
        self.assertEqual(context["stream_context"]["status"], "partial")
        self.assertEqual(context["stream_context"]["pairs_total"], 0)
        self.assertEqual(context["stream_context"]["payload_snippets_total"], 2)
        self.assertEqual(context["stream_context"]["timeline_total"], 2)
        self.assertTrue(context["stream_context"]["notes"])

    def test_memory_packet_flow_context_builds_folded_exchanges_and_conversation_diff(self):
        repository = MemoryHistoryRepository(_ConversationDiffSnifferService())

        context = repository.get_packet_flow_context("diff-6")

        self.assertIsNotNone(context)
        self.assertEqual(context["stream_context"]["folded_exchanges_total"], 2)
        self.assertEqual(context["stream_context"]["conversation_diff_total"], 3)
        self.assertEqual(context["stream_context"]["exchanges"][0]["sections"][0]["title"], "Request")
        self.assertEqual(context["stream_context"]["exchanges"][0]["sections"][1]["title"], "Response")
        diff_titles = {item["title"] for item in context["stream_context"]["conversation_diff"]}
        self.assertIn("Request target changed", diff_titles)
        self.assertIn("Response status changed", diff_titles)
        self.assertIn("Payload snippet changed", diff_titles)


class SQLiteHistoryRepositoryTests(unittest.TestCase):
    def test_sqlite_alert_queries_keep_enriched_fields(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        length INTEGER,
                        country TEXT,
                        org TEXT,
                        summary TEXT,
                        is_alert INTEGER DEFAULT 0,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        l7 TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        tls_version TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_reason_unavailable TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        attack_type TEXT,
                        score REAL,
                        detail TEXT,
                        severity TEXT,
                        engine TEXT,
                        score_raw REAL,
                        incident_id TEXT,
                        incident_count INTEGER,
                        incident_score REAL,
                        packet_id TEXT,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_reason_unavailable TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO alerts (
                        ts, src, dst, proto, attack_type, score, detail,
                        severity, engine, score_raw, incident_id,
                        incident_count, incident_score, packet_id, remote_ip,
                        app_protocol, app_category, app_confidence, dns_qname,
                        http_host, http_path, sni
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "10:00:00",
                        "8.8.8.8",
                        "10.0.0.2",
                        "TCP",
                        "Burst",
                        0.95,
                        "detail",
                        "HIGH",
                        "RULE",
                        0.4,
                        "inc-9",
                        2,
                        0.88,
                        "mem-pkt-4",
                        "8.8.8.8",
                        "HTTPS",
                        "web",
                        "high",
                        None,
                        "example.com",
                        "/admin",
                        "example.com",
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            alerts = repository.list_alerts(AlertListQuery(limit=50, offset=0))
            detail = repository.get_alert_detail("1")

            self.assertEqual(alerts["items"][0]["severity"], "HIGH")
            self.assertEqual(alerts["items"][0]["engine"], "RULE")
            self.assertEqual(alerts["items"][0]["incident_id"], "inc-9")
            self.assertEqual(alerts["items"][0]["app_protocol"], "HTTPS")
            self.assertEqual(detail["packet_id"], "mem-pkt-4")
            self.assertEqual(detail["remote_ip"], "8.8.8.8")
            self.assertEqual(detail["http_host"], "example.com")

    def test_sqlite_only_remote_filter_excludes_ipv6_local_flows(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        length INTEGER,
                        country TEXT,
                        org TEXT,
                        summary TEXT,
                        is_alert INTEGER DEFAULT 0,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        l7 TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        tls_version TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_reason_unavailable TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO packets (
                        ts, src, dst, proto, sport, dport, length,
                        country, org, summary, is_alert, remote_ip,
                        app_protocol, app_category, app_confidence, l7,
                        dns_qname, http_host, http_path, sni, tls_version
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("10:00:00", "fd00::10", "fd00::20", "TCP", 1234, 443, 60, None, None, "ipv6-local", 0, "fd00::20", "HTTPS", "web", "high", None, None, None, None, None, "TLS1.3"),
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            result = repository.list_packets(PacketListQuery(only_remote=True))

            self.assertEqual(result["total"], 0)
            self.assertEqual(result["items"], [])

    def test_async_wrapper_matches_sync_result(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        length INTEGER,
                        country TEXT,
                        org TEXT,
                        summary TEXT,
                        is_alert INTEGER DEFAULT 0,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        l7 TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        tls_version TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_reason_unavailable TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO packets (
                        ts, src, dst, proto, sport, dport, length,
                        country, org, summary, is_alert, remote_ip,
                        app_protocol, app_category, app_confidence, l7,
                        dns_qname, http_host, http_path, sni, tls_version
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("10:00:00", "10.0.0.1", "8.8.8.8", "TCP", 1234, 80, 60, "US", "Example", "hello", 1, "8.8.8.8", "HTTP", "web", "high", "HTTP GET /", None, "example.com", "/", None, None),
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            sync_result = repository.list_packets(PacketListQuery(text="hello", limit=50, offset=0))
            async_result = asyncio.run(repository.alist_packets(PacketListQuery(text="hello", limit=50, offset=0)))

            self.assertEqual(sync_result, async_result)

    def test_sqlite_normalization_prefers_public_peer_as_remote_ip(self):
        row = (
            1,
            "10:00:00",
            "192.168.1.10",
            "8.8.8.8",
            "TCP",
            1234,
            443,
            60,
            "US",
            "Example",
            "hello",
            0,
            "192.168.1.1",
            "HTTPS",
            "web",
            "high",
            None,
            None,
            None,
            None,
            None,
            "TLS1.3",
            4242,
            "browser.exe",
            4000,
            "explorer.exe",
            "C:/Program Files/Browser/browser.exe",
            "high",
            None,
            "psutil",
        )

        normalized = SQLiteHistoryRepository._normalize_packet_row(row)

        self.assertEqual(normalized["remote_ip"], "8.8.8.8")

    def test_sqlite_packet_flow_context_aggregates_flow_stats(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        length INTEGER,
                        country TEXT,
                        org TEXT,
                        summary TEXT,
                        is_alert INTEGER DEFAULT 0,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        l7 TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        tls_version TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_reason_unavailable TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        attack_type TEXT,
                        score REAL,
                        detail TEXT,
                        severity TEXT,
                        engine TEXT,
                        score_raw REAL,
                        incident_id TEXT,
                        incident_count INTEGER,
                        incident_score REAL,
                        packet_id TEXT,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_reason_unavailable TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.executemany(
                    """
                    INSERT INTO packets (
                        ts, src, dst, proto, sport, dport, length,
                        country, org, summary, is_alert, remote_ip,
                        app_protocol, app_category, app_confidence, l7,
                        dns_qname, http_host, http_path, sni, tls_version
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        ("10:00:04", "192.168.1.10", "8.8.8.8", "TCP", 55000, 443, 120, None, None, "request-1", 0, "8.8.8.8", None, None, None, None, None, None, None, None, None),
                        ("10:00:05", "192.168.1.10", "8.8.8.8", "TCP", 55000, 443, 150, None, None, "request-2", 0, "8.8.8.8", None, None, None, None, None, None, None, None, None),
                        ("10:00:06", "8.8.8.8", "192.168.1.10", "TCP", 443, 55000, 220, None, None, "response", 1, "8.8.8.8", None, None, None, None, None, None, None, None, None),
                        ("10:00:07", "192.168.1.10", "8.8.8.8", "TCP", 55001, 80, 90, None, None, "other-port", 0, "8.8.8.8", None, None, None, None, None, None, None, None, None),
                    ],
                )
                conn.execute(
                    """
                    INSERT INTO alerts (
                        ts, src, dst, proto, attack_type, score, detail,
                        severity, engine, score_raw, incident_id,
                        incident_count, incident_score, packet_id, remote_ip,
                        app_protocol, app_category, app_confidence, dns_qname,
                        http_host, http_path, sni
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("10:00:06", "8.8.8.8", "192.168.1.10", "TCP", "Interesting", 0.8, "same flow", "MEDIUM", "RULE", 0.4, None, 1, 0.8, "3", "8.8.8.8", None, None, None, None, None, None, None),
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            context = repository.get_packet_flow_context("3")

            self.assertIsNotNone(context)
            self.assertEqual(context["flow_packets_total"], 3)
            self.assertEqual(context["flow_bytes_in"], 220)
            self.assertEqual(context["flow_bytes_out"], 270)
            self.assertEqual(context["same_peer_packets_total"], 4)
            self.assertEqual(context["same_port_packets_total"], 3)
            self.assertEqual(context["flow_alerts_total"], 1)
            self.assertEqual(context["first_seen"], "10:00:04")
            self.assertEqual(context["last_seen"], "10:00:06")
            self.assertEqual(len(context["related_packets"]), 2)

    def test_sqlite_packet_flow_context_includes_multi_host_correlation(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        length INTEGER,
                        country TEXT,
                        org TEXT,
                        summary TEXT,
                        is_alert INTEGER DEFAULT 0,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        l7 TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        tls_version TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_reason_unavailable TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        attack_type TEXT,
                        score REAL,
                        detail TEXT,
                        severity TEXT,
                        engine TEXT,
                        score_raw REAL,
                        incident_id TEXT,
                        incident_count INTEGER,
                        incident_score REAL,
                        packet_id TEXT,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        dns_qname TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        sni TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_reason_unavailable TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.executemany(
                    """
                    INSERT INTO packets (
                        ts, src, dst, proto, sport, dport, length,
                        country, org, summary, is_alert, remote_ip,
                        app_protocol, app_category, app_confidence, l7,
                        dns_qname, http_host, http_path, sni, tls_version
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        ("10:00:01", "192.168.1.10", "8.8.8.8", "TCP", 55000, 443, 110, None, None, "selected-request", 0, "8.8.8.8", None, None, None, None, None, None, None, None, None),
                        ("10:00:02", "8.8.8.8", "192.168.1.10", "TCP", 443, 55000, 140, None, None, "selected-response", 0, "8.8.8.8", None, None, None, None, None, None, None, None, None),
                        ("10:00:03", "192.168.1.10", "1.1.1.1", "TCP", 55001, 443, 84, None, None, "fanout-1", 0, "1.1.1.1", None, None, None, None, None, None, None, None, None),
                        ("10:00:04", "192.168.1.10", "9.9.9.9", "TCP", 55002, 443, 86, None, None, "fanout-2", 0, "9.9.9.9", None, None, None, None, None, None, None, None, None),
                        ("10:00:05", "192.168.1.10", "8.8.4.4", "TCP", 55003, 443, 88, None, None, "fanout-3", 0, "8.8.4.4", None, None, None, None, None, None, None, None, None),
                        ("10:00:06", "192.168.1.10", "4.4.4.4", "TCP", 55004, 8443, 92, None, None, "alt-service", 0, "4.4.4.4", None, None, None, None, None, None, None, None, None),
                        ("10:00:07", "192.168.1.10", "8.8.8.8", "TCP", 55005, 443, 96, None, None, "repeat-peer", 0, "8.8.8.8", None, None, None, None, None, None, None, None, None),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            context = repository.get_packet_flow_context("2")

            self.assertIsNotNone(context)
            self.assertEqual(context["sample_packets"], 7)
            self.assertIn("Fan-out pattern observed", context["behavior_labels"])
            self.assertIn("Sweep pattern candidate", context["behavior_labels"])
            self.assertEqual(context["host_correlation"]["remote_hosts_total"], 5)
            self.assertEqual(context["host_correlation"]["selected_remote_sessions_total"], 2)
            self.assertEqual(context["port_correlation"]["pattern"], "Sweep pattern candidate")
            self.assertEqual(context["port_correlation"]["remote_port_remote_hosts_total"], 4)
            self.assertEqual(context["conversation_clusters"][0]["title"], "8.8.8.8 (TCP)")

    def test_sqlite_packet_flow_context_detects_beacon_like_repetition(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        direction TEXT,
                        length INTEGER,
                        summary TEXT,
                        remote_ip TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        direction TEXT,
                        attack_type TEXT,
                        score REAL,
                        detail TEXT,
                        severity TEXT,
                        engine TEXT,
                        packet_id TEXT,
                        remote_ip TEXT,
                        pid INTEGER,
                        process_name TEXT
                    )
                    """
                )
                conn.executemany(
                    """
                    INSERT INTO packets (
                        ts, src, dst, proto, sport, dport, direction, length, summary,
                        remote_ip, pid, process_name, parent_pid, parent_process_name,
                        executable_path, attribution_confidence, attribution_source
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        ("10:00:00", "192.168.1.50", "203.0.113.10", "TCP", 51000, 443, "OUTGOING", 68, "beacon-1-req", "203.0.113.10", 7711, "agent.exe", 7000, "services.exe", "C:/Program Files/Agent/agent.exe", "high", "psutil"),
                        ("10:00:01", "203.0.113.10", "192.168.1.50", "TCP", 443, 51000, "INCOMING", 72, "beacon-1-resp", "203.0.113.10", 7711, "agent.exe", 7000, "services.exe", "C:/Program Files/Agent/agent.exe", "high", "psutil"),
                        ("10:00:15", "192.168.1.50", "203.0.113.10", "TCP", 51001, 443, "OUTGOING", 68, "beacon-2-req", "203.0.113.10", 7711, "agent.exe", 7000, "services.exe", "C:/Program Files/Agent/agent.exe", "high", "psutil"),
                        ("10:00:16", "203.0.113.10", "192.168.1.50", "TCP", 443, 51001, "INCOMING", 72, "beacon-2-resp", "203.0.113.10", 7711, "agent.exe", 7000, "services.exe", "C:/Program Files/Agent/agent.exe", "high", "psutil"),
                        ("10:00:30", "192.168.1.50", "203.0.113.10", "TCP", 51002, 443, "OUTGOING", 68, "beacon-3-req", "203.0.113.10", 7711, "agent.exe", 7000, "services.exe", "C:/Program Files/Agent/agent.exe", "high", "psutil"),
                        ("10:00:31", "203.0.113.10", "192.168.1.50", "TCP", 443, 51002, "INCOMING", 72, "beacon-3-resp", "203.0.113.10", 7711, "agent.exe", 7000, "services.exe", "C:/Program Files/Agent/agent.exe", "high", "psutil"),
                        ("10:00:45", "192.168.1.50", "203.0.113.10", "TCP", 51003, 443, "OUTGOING", 68, "beacon-4-req", "203.0.113.10", 7711, "agent.exe", 7000, "services.exe", "C:/Program Files/Agent/agent.exe", "high", "psutil"),
                        ("10:00:46", "203.0.113.10", "192.168.1.50", "TCP", 443, 51003, "INCOMING", 72, "beacon-4-resp", "203.0.113.10", 7711, "agent.exe", 7000, "services.exe", "C:/Program Files/Agent/agent.exe", "high", "psutil"),
                    ],
                )
                conn.execute(
                    """
                    INSERT INTO alerts (
                        ts, src, dst, proto, sport, dport, direction, attack_type,
                        score, detail, severity, engine, packet_id, remote_ip, pid, process_name
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("10:00:45", "192.168.1.50", "203.0.113.10", "TCP", 51003, 443, "OUTGOING", "Suspicious Recurrence", 0.66, "linked beacon alert", "MEDIUM", "RULE", "7", "203.0.113.10", 7711, "agent.exe"),
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            packet_context = repository.get_packet_flow_context("7")
            alert_context = repository.get_alert_context("1")

            self.assertIn("Repeated short connections observed", packet_context["behavior_labels"])
            self.assertIn("Beacon-like repetition observed", packet_context["behavior_labels"])
            self.assertTrue(any(item["id"] == "beacon_like_repetition" for item in packet_context["behavior_evidence"]))
            self.assertIn("Beacon-like repetition observed", alert_context["behavior_labels"])

    def test_sqlite_packet_flow_context_reconstructs_http_stream_summary(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        direction TEXT,
                        length INTEGER,
                        summary TEXT,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        http_method TEXT,
                        http_host TEXT,
                        http_path TEXT,
                        http_status INTEGER,
                        http_reason TEXT,
                        http_content_type TEXT,
                        payload_ascii TEXT
                    )
                    """
                )
                conn.executemany(
                    """
                    INSERT INTO packets (
                        ts, src, dst, proto, sport, dport, direction, length, summary, remote_ip,
                        app_protocol, http_method, http_host, http_path, http_status, http_reason,
                        http_content_type, payload_ascii
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        ("10:00:00", "192.168.1.70", "93.184.216.34", "TCP", 53000, 443, "OUTGOING", 90, "tcp-setup", "93.184.216.34", None, None, None, None, None, None, None, None),
                        ("10:00:01", "192.168.1.70", "93.184.216.34", "TCP", 53000, 443, "OUTGOING", 140, "http-request", "93.184.216.34", "HTTP", "POST", "example.com", "/login", None, None, None, "POST /login HTTP/1.1 Host: example.com"),
                        ("10:00:02", "192.168.1.70", "93.184.216.34", "TCP", 53000, 443, "OUTGOING", 120, "http-request-body", "93.184.216.34", "HTTP", None, None, None, None, None, None, "authorization=token&state=ready"),
                        ("10:00:03", "93.184.216.34", "192.168.1.70", "TCP", 443, 53000, "INCOMING", 220, "http-response", "93.184.216.34", "HTTP", None, None, None, 200, "OK", "application/json", "HTTP/1.1 200 OK {\"ok\":true}"),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            context = repository.get_packet_flow_context("4")

            self.assertEqual(context["stream_context"]["status"], "complete")
            self.assertEqual(context["stream_context"]["requests_total"], 1)
            self.assertEqual(context["stream_context"]["responses_total"], 1)
            self.assertEqual(context["stream_context"]["pairs_total"], 1)
            self.assertEqual(context["stream_context"]["folded_exchanges_total"], 1)
            self.assertEqual(context["stream_context"]["conversation_diff_total"], 0)
            self.assertEqual(context["stream_context"]["request_response_pairs"][0]["response_title"], "200 OK")
            self.assertEqual(context["stream_context"]["timeline_total"], 4)
            self.assertEqual(context["stream_context"]["navigation"]["previous_packet_id"], "3")
            self.assertEqual(context["stream_context"]["navigation"]["next_packet_id"], None)

    def test_sqlite_history_detail_rehydrates_protocol_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        capture_id TEXT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        direction TEXT,
                        length INTEGER,
                        summary TEXT,
                        is_alert INTEGER DEFAULT 0,
                        remote_ip TEXT,
                        app_protocol TEXT,
                        app_category TEXT,
                        app_confidence TEXT,
                        protocol_basis TEXT,
                        protocol_notes TEXT,
                        protocol_handshake TEXT,
                        protocol_unusual_port INTEGER,
                        l7 TEXT,
                        payload_hex TEXT,
                        payload_ascii TEXT,
                        payload_binary_like INTEGER,
                        payload_entropy REAL,
                        payload_printable_ratio REAL
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO packets (
                        capture_id, ts, src, dst, proto, sport, dport, direction,
                        length, summary, is_alert, remote_ip, app_protocol, app_category,
                        app_confidence, protocol_basis, protocol_notes, protocol_handshake,
                        protocol_unusual_port, l7, payload_hex, payload_ascii,
                        payload_binary_like, payload_entropy, payload_printable_ratio
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "cap-4500",
                        "10:00:00",
                        "193.111.235.38",
                        "192.168.1.10",
                        "UDP",
                        4500,
                        50000,
                        "INCOMING",
                        92,
                        "nat-t-candidate",
                        1,
                        "193.111.235.38",
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        "00 00 00 00 45 00 00 54",
                        "....E..T",
                        1,
                        4.7,
                        0.1,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            detail = repository.get_packet_detail("1")

            self.assertEqual(detail["capture_id"], "cap-4500")
            self.assertEqual(detail["app_protocol"], "IPsec NAT-T")
            self.assertEqual(detail["protocol_handshake"], "NAT-T tunnel candidate")
            self.assertIn("UDP/4500", detail["protocol_basis"])
            self.assertTrue(detail["payload_binary_like"])

    def test_sqlite_alert_context_links_capture_id_flow_and_process(self):
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "history.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        capture_id TEXT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        direction TEXT,
                        length INTEGER,
                        summary TEXT,
                        remote_ip TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT,
                        src TEXT,
                        dst TEXT,
                        proto TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        direction TEXT,
                        attack_type TEXT,
                        score REAL,
                        detail TEXT,
                        severity TEXT,
                        engine TEXT,
                        packet_id TEXT,
                        remote_ip TEXT,
                        pid INTEGER,
                        process_name TEXT,
                        parent_pid INTEGER,
                        parent_process_name TEXT,
                        executable_path TEXT,
                        attribution_confidence TEXT,
                        attribution_source TEXT
                    )
                    """
                )
                conn.executemany(
                    """
                    INSERT INTO packets (
                        capture_id, ts, src, dst, proto, sport, dport, direction,
                        length, summary, remote_ip, pid, process_name, parent_pid,
                        parent_process_name, executable_path, attribution_confidence,
                        attribution_source
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        ("cap-1", "10:00:05", "192.168.1.10", "8.8.8.8", "TCP", 55000, 443, "OUTGOING", 120, "selected-request", "8.8.8.8", 4242, "browser.exe", 4000, "explorer.exe", "C:/Program Files/Browser/browser.exe", "high", "psutil"),
                        ("cap-2", "10:00:06", "8.8.8.8", "192.168.1.10", "TCP", 443, 55000, "INCOMING", 220, "selected-response", "8.8.8.8", 4242, "browser.exe", 4000, "explorer.exe", "C:/Program Files/Browser/browser.exe", "high", "psutil"),
                        ("cap-3", "10:00:07", "192.168.1.10", "8.8.8.8", "TCP", 55001, 443, "OUTGOING", 96, "same-remote", "8.8.8.8", 4242, "browser.exe", 4000, "explorer.exe", "C:/Program Files/Browser/browser.exe", "high", "psutil"),
                    ],
                )
                conn.executemany(
                    """
                    INSERT INTO alerts (
                        ts, src, dst, proto, sport, dport, direction, attack_type,
                        score, detail, severity, engine, packet_id, remote_ip, pid,
                        process_name, parent_pid, parent_process_name, executable_path,
                        attribution_confidence, attribution_source
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        ("10:00:06", "8.8.8.8", "192.168.1.10", "TCP", 443, 55000, "INCOMING", "Suspicious Tunnel", 0.9, "linked packet alert", "HIGH", "RULE", "cap-2", "8.8.8.8", 4242, "browser.exe", 4000, "explorer.exe", "C:/Program Files/Browser/browser.exe", "high", "psutil"),
                        ("10:00:07", "8.8.8.8", "192.168.1.10", "TCP", 443, 55001, "INCOMING", "Remote Recurrence", 0.6, "same remote different flow", "MEDIUM", "RULE", "cap-3", "8.8.8.8", 4242, "browser.exe", 4000, "explorer.exe", "C:/Program Files/Browser/browser.exe", "high", "psutil"),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            repository = SQLiteHistoryRepository(db_path=str(db_path))
            context = repository.get_alert_context("1")

            self.assertIsNotNone(context)
            self.assertEqual(context["packet_id"], "cap-2")
            self.assertEqual(context["linked_packet_id"], 2)
            self.assertEqual(context["process_correlation"]["label"], "browser.exe")
            self.assertEqual(context["alert_correlation"]["peer_alerts_total"], 2)
            self.assertEqual(len(context["same_remote_alerts"]), 1)
            self.assertEqual(len(context["related_flows"]), 1)
            self.assertTrue(any(group["title"] == "Packet to Alert Chain" for group in context["root_cause_groups"]))


if __name__ == "__main__":
    unittest.main()
