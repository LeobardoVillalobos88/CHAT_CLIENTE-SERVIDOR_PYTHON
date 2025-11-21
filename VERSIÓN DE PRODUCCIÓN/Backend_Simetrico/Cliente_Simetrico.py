import socket
import ssl
import hmac
import hashlib
import json
import os
from dotenv import load_dotenv

load_dotenv()
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "ClavePorDefecto").encode("utf-8")

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False      
context.verify_mode = ssl.CERT_NONE 

# FUNCIONES AUXILIARES
def firmar(msg: str) -> str:
    return hmac.new(SECRET_KEY, msg.encode('utf-8'), hashlib.sha256).hexdigest()

def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def recibir_id(sock: ssl.SSLSocket) -> int:
    buffer = b""
    while b"\n" not in buffer:
        chunk = sock.recv(64)
        if not chunk:
            break
        buffer += chunk
    try:
        linea = buffer.decode('utf-8', errors='ignore').strip()
        if linea.startswith("ID:"):
            return int(linea.split(":", 1)[1])
    except Exception:
        pass
    return -1

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = context.wrap_socket(sock, server_hostname=HOST)
    conn.connect((HOST, PORT))

    cid = recibir_id(conn)
    etiqueta = f"Cliente {cid}" if cid > 0 else "Cliente"

    f = conn.makefile('w', encoding='utf-8', newline='\n')

    print("Conexión segura establecida (SSL/TLS activo).")
    print("Escribe (salir) para terminar el chat:")

    try:
        while True:
            mensaje = input(f"{etiqueta}: ")
            if mensaje.lower() == "salir":
                break
            paquete = {
                "msg": mensaje,
                "sha": sha256_hex(mensaje),
                "hmac": firmar(mensaje)
            }
            f.write(json.dumps(paquete) + "\n")
            f.flush()
    finally:
        try:
            f.close()
        except Exception:
            pass
        conn.close()
        print("Conexión cerrada.")

if __name__ == "__main__":
    main()