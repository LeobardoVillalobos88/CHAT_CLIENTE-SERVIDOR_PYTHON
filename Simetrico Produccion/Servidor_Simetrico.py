import socket
import ssl
import threading
import hmac
import hashlib
import json
import os
from dotenv import load_dotenv

load_dotenv()
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "ClavePorDefecto").encode("utf-8")

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

lock = threading.Lock()
clientes = {}
siguiente_id = 1

def verificar_hmac(msg: str, firma_hex: str) -> bool:
    mac = hmac.new(SECRET_KEY, msg.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, firma_hex)

def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def manejar_cliente(conn: ssl.SSLSocket, addr):
    global siguiente_id
    with lock:
        cid = siguiente_id
        siguiente_id += 1
        clientes[conn] = {"id": cid, "addr": addr}

    print(f"[CONEXIÓN] Cliente #{cid} desde {addr} (SSL Activo)")

    try:
        conn.sendall(f"ID:{cid}\n".encode('utf-8'))
    except Exception:
        conn.close()
        with lock:
            clientes.pop(conn, None)
        print(f"[DESCONECTADO] Cliente #{cid} (falló al enviar ID)")
        return

    f = conn.makefile('r', encoding='utf-8', newline='\n')
    try:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                paquete = json.loads(linea)
                msg   = paquete.get("msg", "")
                firma = paquete.get("hmac", "")
                sha   = paquete.get("sha", "")
            except json.JSONDecodeError:
                print(f"[!] Cliente #{cid}: JSON inválido.")
                continue

            if not msg or not sha:
                print(f"[!] Cliente #{cid}: paquete incompleto.")
                continue

            sha_ok = hmac.compare_digest(sha256_hex(msg), sha.lower())
            hmac_ok = verificar_hmac(msg, firma) if firma else False

            if sha_ok and hmac_ok:
                print(f"[OK] Cliente #{cid}: {msg}  (SHA OK, HMAC OK)")
            elif sha_ok:
                print(f"[OK] Cliente #{cid}: {msg}  (SHA OK, HMAC NO)")
            else:
                print(f"[X] Cliente #{cid}: SHA no coincide. Mensaje rechazado.")
    except Exception as e:
        print(f"[ERROR] Cliente #{cid}: {e}")
    finally:
        try:
            f.close()
        except Exception:
            pass
        conn.close()
        with lock:
            clientes.pop(conn, None)
        print(f"[DESCONECTADO] Cliente #{cid} ({addr})")
        
def main():
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((HOST, PORT))
    bindsocket.listen(5)

    print(f"Servidor escuchando en {HOST}:{PORT} (modo seguro SSL/TLS)")

    try:
        while True:
            newsocket, fromaddr = bindsocket.accept()
            conn_ssl = context.wrap_socket(newsocket, server_side=True)
            hilo = threading.Thread(target=manejar_cliente, args=(conn_ssl, fromaddr), daemon=True)
            hilo.start()
    except KeyboardInterrupt:
        print("\nCerrando servidor…")
    finally:
        bindsocket.close()

if __name__ == "__main__":
    main()