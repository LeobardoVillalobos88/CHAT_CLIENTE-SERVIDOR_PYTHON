import socket
import ssl
import threading
import hmac
import hashlib
import json
import os
import base64
import time

from dotenv import load_dotenv
from FirmaDigital.firma_digital import firmar_pdf, firmar_archivo_generico, sha256_bytes, generar_llaves

load_dotenv()
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "ClavePorDefecto").encode("utf-8")

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

CARPETA_RECIBIDOS = "archivos_recibidos"
os.makedirs(CARPETA_RECIBIDOS, exist_ok=True)

lock = threading.Lock()
clientes = {}
siguiente_id = 1

def verificar_hmac(msg: str, firma_hex: str) -> bool:
    mac = hmac.new(SECRET_KEY, msg.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, firma_hex)


def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def broadcast_mensaje(mensaje_enviado: dict, cliente_origen_id: int):
    """Reenvía un mensaje validado a todos los clientes conectados (solo chat)."""
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
            if datos["id"] != cliente_origen_id:
                try:
                    datos["writer"].write(mensaje_json)
                    datos["writer"].flush()
                except Exception:
                    clientes_a_eliminar.append(conn)

        for conn in clientes_a_eliminar:
            if conn in clientes:
                try:
                    clientes[conn]["writer"].close()
                    conn.close()
                except Exception:
                    pass
                clientes.pop(conn, None)

def manejar_archivo(paquete: dict, cid: int):
    nombre = paquete.get("nombre")
    data_b64 = paquete.get("data")
    sha_remoto = paquete.get("sha", "").lower()

    if not nombre or not data_b64 or not sha_remoto:
        print(f"[ARCHIVO] Cliente #{cid}: paquete incompleto para archivo.")
        return

    try:
        data = base64.b64decode(data_b64)
    except Exception as e:
        print(f"[ARCHIVO] Cliente #{cid}: error al decodificar base64: {e}")
        return

    sha_local = sha256_bytes(data)
    if not hmac.compare_digest(sha_local.lower(), sha_remoto):
        print(f"[ARCHIVO] Cliente #{cid}: SHA no coincide. Archivo rechazado.")
        return

    ruta_guardado = os.path.join(CARPETA_RECIBIDOS, f"cliente{cid}_{nombre}")
    try:
        with open(ruta_guardado, "wb") as f:
            f.write(data)
    except Exception as e:
        print(f"[ARCHIVO] Cliente #{cid}: error al guardar archivo: {e}")
        return

    print(f"[ARCHIVO] Cliente #{cid}: archivo guardado en {ruta_guardado}")
    generar_llaves()

    if nombre.lower().endswith(".pdf"):
        try:
            ruta_pdf_firmado, ruta_sig, info = firmar_pdf(ruta_guardado, cliente_id=cid)
            print(f"[ARCHIVO] Cliente #{cid}: PDF firmado -> {ruta_pdf_firmado}")
            print(f"[ARCHIVO] Firma (.sig) -> {ruta_sig}")
        except Exception as e:
            print(f"[ARCHIVO] Cliente #{cid}: error al firmar PDF: {e}")
    else:
        try:
            ruta_sig, info = firmar_archivo_generico(ruta_guardado, cliente_id=cid)
            print(f"[ARCHIVO] Cliente #{cid}: archivo firmado (no PDF) -> {ruta_sig}")
        except Exception as e:
            print(f"[ARCHIVO] Cliente #{cid}: error al firmar archivo: {e}")

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
        for linea in file_reader:
            linea = linea.strip()
            if not linea:
                continue

            try:
                paquete = json.loads(linea)
            except json.JSONDecodeError:
                print(f"[!] Cliente #{cid}: JSON inválido.")
                continue

            tipo = paquete.get("type", "chat")

            if tipo == "archivo":
                manejar_archivo(paquete, cid)
                continue

            msg = paquete.get("msg", "")
            firma = paquete.get("hmac", "")
            sha = paquete.get("sha", "")

            if not msg or not sha:
                print(f"[!] Cliente #{cid}: paquete incompleto para chat.")
                continue

            sha_ok = hmac.compare_digest(sha256_hex(msg), sha.lower())
            hmac_ok = verificar_hmac(msg, firma) if firma else False

            if sha_ok and hmac_ok:
                print(f"[OK] Cliente #{cid}: {msg}  (SHA OK, HMAC OK)")
                paquete["timestamp"] = time.strftime("%H:%M:%S")
                broadcast_mensaje(paquete, cid)
            elif sha_ok:
                print(f"[OK] Cliente #{cid}: {msg}  (SHA OK, HMAC NO)")
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