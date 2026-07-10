import socket
from concurrent.futures import ThreadPoolExecutor


def scan_tcp_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            return {
                "port": port,
                "protocol": "TCP",
                "status": "OPEN"
            }

    except:
        pass

    finally:
        sock.close()

    return None


def tcp_scan(target, start_port, end_port):

    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:

        results = executor.map(
            lambda port: scan_tcp_port(target, port),
            range(start_port, end_port + 1)
        )

        for result in results:
            if result:
                open_ports.append(result)

    return open_ports