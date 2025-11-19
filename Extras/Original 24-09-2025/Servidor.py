import socket
import threading

host = '127.0.0.1'
port = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()
print(f"Servidor escuchando en {host}:{port}")

def manejar_cliente(conn, addr):
    print(f"Conexión desde {addr}")
    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                break
            print(f"Cliente {addr}: {data}")
        except:
            break
    conn.close()
    print(f"Cliente {addr} desconectado")

while True:
    conn, addr = server.accept()
    thread = threading.Thread(target=manejar_cliente, args=(conn, addr))
    thread.start()