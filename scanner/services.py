import socket


def detect_service(target, port):
    try:
        service = socket.getservbyport(port)

        return service

    except:
        return "Unknown"