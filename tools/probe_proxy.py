import socket, sys, time

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 7899))
srv.listen(8)
srv.settimeout(1.0)
print("LISTENING 127.0.0.1:7899", flush=True)
deadline = time.time() + float(sys.argv[1] if len(sys.argv) > 1 else 20)
hits = 0
while time.time() < deadline:
    try:
        c, addr = srv.accept()
    except socket.timeout:
        continue
    c.settimeout(2.0)
    try:
        data = c.recv(200)
    except Exception:
        data = b""
    hits += 1
    print("HIT from %s: %r" % (addr, data[:120]), flush=True)
    try:
        c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        c.close()
    except Exception:
        pass
print("DONE hits=%d" % hits, flush=True)
