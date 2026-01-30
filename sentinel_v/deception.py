import paramiko
import socket
import threading
import logging

class DynamicHoneypot:
    def __init__(self, host='0.0.0.0', port=2222, key_file=None):
        self.host = host
        self.port = port
        self.server = paramiko.Transport((host, port))
        host_key = paramiko.RSAKey.generate(1024) if not key_file else paramiko.RSAKey.from_private_key_file(key_file)
        self.server.add_server_key(host_key)
        logging.basicConfig(filename='honeypot.log', level=logging.INFO)
    
    def handle_client(self, client, addr):
        transport = paramiko.Transport(client)
        transport.add_server_key(paramiko.RSAKey.generate(1024))
        server = paramiko.ServerInterface()
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan:
            logging.info(f"Connection from {addr}: {chan.recv(1024).decode()}")
            chan.send("Invalid credentials\n")
            chan.close()
    
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(100)
        while True:
            client, addr = sock.accept()
            threading.Thread(target=self.handle_client, args=(client, addr)).start()

# Example
if __name__ == "__main__":
    honeypot = DynamicHoneypot()
    honeypot.start()
