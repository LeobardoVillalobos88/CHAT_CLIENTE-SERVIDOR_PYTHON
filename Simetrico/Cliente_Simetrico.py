import socket
import hmac
import hashlib
import json

HOST = '127.0.0.1'
PORT = 5000
SECRET_KEY = b"SergioLeobardoJassielCalebAlejandro"

def firmar(msg: str) -> str:
    return hmac.new(SECRET_KEY, msg.encode('utf-8'), hashlib.sha256).hexdigest()

# SHA-256 simple (checksum por mensaje)
def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def recibir_id(sock: socket.socket) -> int:
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
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    cid = recibir_id(client)
    etiqueta = f"Cliente {cid}" if cid > 0 else "Cliente"

    f = client.makefile('w', encoding='utf-8', newline='\n')

    print("Escribe (salir) para terminar de chatear: ")
    try:
        while True:
            mensaje = input(f"{etiqueta}: ")
            if mensaje.lower() == "salir":
                break
            paquete = {
                "msg": mensaje,
                "sha": sha256_hex(mensaje),   # SHA por mensaje
                "hmac": firmar(mensaje)       # Se mantiene HMAC (simétrico)
            }
            f.write(json.dumps(paquete) + "\n")
            f.flush()
    finally:
        try:
            f.close()
        except Exception:
            pass
        client.close()

if __name__ == "__main__":
    main()