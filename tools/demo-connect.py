#!/usr/bin/env python3
"""Loopback connect to 127.0.0.1:4444 through a real listener (for demos)."""
import socket, time
s = socket.socket(); s.bind(("127.0.0.1", 4444)); s.listen(1)
time.sleep(0.4)
c = socket.socket(); c.connect(("127.0.0.1", 4444))
a, _ = s.accept()
c.close(); a.close(); s.close()
