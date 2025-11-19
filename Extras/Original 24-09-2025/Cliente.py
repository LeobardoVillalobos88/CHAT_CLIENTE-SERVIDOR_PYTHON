import socket

host = '127.0.0.1'
port=5000

client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port))

print("Escribe (salir) para terminar de chatear: ")
while True:
    mensaje=input("Cliente: ")
    if mensaje.lower() == "salir":
        break
    client.send(mensaje.encode('utf-8'))
client.close()