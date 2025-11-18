import socket
import ssl
import threading
import hmac
import hashlib
import json
import os
from dotenv import load_dotenv

# CARGA DE VARIABLES DE ENTORNO
load_dotenv()
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "ClavePorDefecto").encode("utf-8")

# CONFIGURACIÓN SSL/TLS
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

# VARIABLES GLOBALES
lock = threading.Lock()
clientes = {}  # {conn: {"id": cid, "addr": addr, "writer": file_writer}}
siguiente_id = 1

# FUNCIONES AUXILIARES
def verificar_hmac(msg: str, firma_hex: str) -> bool:
    mac = hmac.new(SECRET_KEY, msg.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, firma_hex)

def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

# FUNCIÓN PARA REENVIAR MENSAJES A TODOS LOS CLIENTES
def broadcast_mensaje(mensaje_enviado: dict, cliente_origen_id: int):
    """Reenvía un mensaje validado a todos los clientes conectados"""
    mensaje_broadcast = {
        "type": "mensaje",
        "cliente_id": cliente_origen_id,
        "mensaje": mensaje_enviado.get("msg", ""),
        "timestamp": mensaje_enviado.get("timestamp", "")
    }
    mensaje_json = json.dumps(mensaje_broadcast) + "\n"
    
    with lock:
        clientes_a_eliminar = []
        for conn, datos in clientes.items():
            if datos["id"] != cliente_origen_id:  # No reenviar al remitente
                try:
                    datos["writer"].write(mensaje_json)
                    datos["writer"].flush()
                except Exception:
                    clientes_a_eliminar.append(conn)
        
        # Eliminar clientes desconectados
        for conn in clientes_a_eliminar:
            if conn in clientes:
                try:
                    clientes[conn]["writer"].close()
                    conn.close()
                except Exception:
                    pass
                clientes.pop(conn, None)

# MANEJO DE CLIENTES
def manejar_cliente(conn: ssl.SSLSocket, addr):
    global siguiente_id
    with lock:
        cid = siguiente_id
        siguiente_id += 1
    
    print(f"[CONEXIÓN] Cliente #{cid} desde {addr} (SSL Activo)")

    try:
        conn.sendall(f"ID:{cid}\n".encode('utf-8'))
        file_writer = conn.makefile('w', encoding='utf-8', newline='\n')
        file_reader = conn.makefile('r', encoding='utf-8', newline='\n')
        
        with lock:
            clientes[conn] = {"id": cid, "addr": addr, "writer": file_writer}
    except Exception:
        conn.close()
        print(f"[DESCONECTADO] Cliente #{cid} (falló al enviar ID)")
        return

    try:
        import time
        for linea in file_reader:
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

            # Verificaciones de seguridad
            sha_ok = hmac.compare_digest(sha256_hex(msg), sha.lower())
            hmac_ok = verificar_hmac(msg, firma) if firma else False

            if sha_ok and hmac_ok:
                print(f"[OK] Cliente #{cid}: {msg}  (SHA OK, HMAC OK)")
                # Reenviar mensaje a todos los demás clientes
                paquete["timestamp"] = time.strftime("%H:%M:%S")
                broadcast_mensaje(paquete, cid)
            elif sha_ok:
                print(f"[OK] Cliente #{cid}: {msg}  (SHA OK, HMAC NO)")
                # Aún así reenviar si SHA es válido
                paquete["timestamp"] = time.strftime("%H:%M:%S")
                broadcast_mensaje(paquete, cid)
            else:
                print(f"[X] Cliente #{cid}: SHA no coincide. Mensaje rechazado.")
    except Exception as e:
        print(f"[ERROR] Cliente #{cid}: {e}")
    finally:
        try:
            file_reader.close()
            file_writer.close()
        except Exception:
            pass
        conn.close()
        with lock:
            clientes.pop(conn, None)
        print(f"[DESCONECTADO] Cliente #{cid} ({addr})")
        
# SERVIDOR PRINCIPAL
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