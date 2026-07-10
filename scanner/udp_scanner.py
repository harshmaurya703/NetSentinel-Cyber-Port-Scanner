import socket


def scan_udp_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)

        sock.sendto(b"", (target, port))

        return {
            "port": port,
            "protocol": "UDP",
            "status": "OPEN|FILTERED"
        }

    except:
        return None

    finally:
        sock.close()


def udp_scan(target, start_port, end_port):
    open_ports = []

    for port in range(start_port, end_port + 1):
        result = scan_udp_port(target, port)

        if result:
            open_ports.append(result)

    return open_ports