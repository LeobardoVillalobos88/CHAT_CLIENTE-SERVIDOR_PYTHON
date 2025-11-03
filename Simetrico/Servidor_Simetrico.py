import socket
import threading
import hmac
import hashlib
import json

HOST = '127.0.0.1'
PORT = 5000
SECRET_KEY = b"SergioLeobardoJassielCalebAlejandro"

lock = threading.Lock()
clientes = {}
siguiente_id = 1

def verificar_hmac(msg: str, firma_hex: str) -> bool:
    mac = hmac.new(SECRET_KEY, msg.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, firma_hex)

# NUEVO: SHA-256 simple
def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def manejar_cliente(conn: socket.socket, addr):
    global siguiente_id
    with lock:
        cid = siguiente_id
        siguiente_id += 1
        clientes[conn] = {"id": cid, "addr": addr}

    print(f"[CONEXIÓN] Cliente #{cid} desde {addr}")

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
                print(f"[!] Cliente #{cid}: JSON inválido: {linea!r}")
                continue

            if not msg or not sha:
                print(f"[!] Cliente #{cid}: paquete incompleto (falta msg o sha): {paquete}")
                continue

            # 1) Verificación obligatoria por consigna: SHA-256
            sha_ok = hmac.compare_digest(sha256_hex(msg), sha.lower())

            # 2) Verificación adicional: HMAC
            hmac_ok = verificar_hmac(msg, firma) if firma else False

            if sha_ok:
                # Cumple la tarea (SHA válido). Mostramos si HMAC coincide o no.
                if hmac_ok:
                    print(f"[OK] Cliente #{cid}: {msg}  (SHA OK, HMAC OK)")
                else:
                    print(f"[OK] Cliente #{cid}: {msg}  (SHA OK, HMAC NO)")
            else:
                print(f"[X] Cliente #{cid}: SHA no coincide. Mensaje descartado.")
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
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Servidor escuchando en {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()
            hilo = threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True)
            hilo.start()
    except KeyboardInterrupt:
        print("\nCerrando servidor…")
    finally:
        server.close()

if __name__ == "__main__":
    main()