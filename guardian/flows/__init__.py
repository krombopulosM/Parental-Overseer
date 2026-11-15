from dataclasses import dataclass


@dataclass
class FlowSample:
    """Cumulative counters for one connection, as reported by a backend."""
    key: str                 # backend-unique id
    tuple: tuple             # (proto, client_ip, client_port, remote_ip, remote_port)
    bytes_up: int
    bytes_down: int
    pkts_up: int = 0
    pkts_down: int = 0
