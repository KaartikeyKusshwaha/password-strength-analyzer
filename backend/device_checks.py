"""Single-target TCP observations on a locally installed SentinelOps instance."""
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

from .scanner import finding

DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5000, 8000, 8080, 8443)


def validate_target(value):
    # No DNS resolution, redirects, metadata services, multicast or broad sweeps.
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Enter one loopback or private LAN IP address, not a hostname or range.")
    rfc1918 = address.version == 4 and any(address in ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    ula = address.version == 6 and address in ipaddress.ip_network("fc00::/7")
    if not (address.is_loopback or rfc1918 or ula) or address.is_multicast or address.is_unspecified or address.is_link_local:
        raise ValueError("Use one authorized loopback or private LAN address. Public, link-local and metadata addresses are excluded.")
    if address.version == 4 and str(address).endswith('.255'):
        raise ValueError("Broadcast-like targets are excluded.")
    return str(address)


def assess(target, ports):
    target = validate_target(target)
    ports = sorted(set(ports))
    if not 1 <= len(ports) <= 64 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError("Choose 1–64 TCP ports between 1 and 65535.")
    def check(port):
        try:
            with socket.create_connection((target, port), timeout=0.5):
                status = "open"
        except ConnectionRefusedError:
            status = "closed"
        except OSError:
            status = "unassessed"
        return {"host": target, "port": port, "status": status}
    with ThreadPoolExecutor(max_workers=8) as pool:
        observations = list(pool.map(check, ports))
    items = [finding("PORT001", evidence=f"TCP listener observed on {target}:{p['port']}. Service identity and exploitability are unverified.", confidence="low", host=target, port=p['port']) for p in observations if p['status'] == 'open']
    return dict(findings=items, observations=observations, error="Some ports could not be assessed." if any(p['status'] == 'unassessed' for p in observations) else None, limits="One authorized IP, selected TCP ports, connect only. An open port is not proof of a vulnerability or public exposure. No UDP, exploit attempts, process identification or OS configuration changes.")
