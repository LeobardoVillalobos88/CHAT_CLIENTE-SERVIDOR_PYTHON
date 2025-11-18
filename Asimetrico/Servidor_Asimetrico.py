import socket
import threading
import json
import hashlib

HOST = '127.0.0.1'
PORT = 5000

lock = threading.Lock()
siguiente_id = 1

def sha256_int(msg: str) -> int:
    h = hashlib.sha256(msg.encode('utf-8')).hexdigest()
    return int(h, 16)

def rsa_verify(sig_hex: str, msg: str, pub_n: int, pub_e: int) -> bool:
    try:
        sig = int(sig_hex, 16)
    except ValueError:
        return False
    h = sha256_int(msg) % pub_n
    ver = pow(sig, pub_e, pub_n)
    return ver == h

def manejar_cliente(conn: socket.socket, addr):
    global siguiente_id
    with lock:
        cid = siguiente_id
        siguiente_id += 1

    print(f"Conexión desde {addr}")
    f = conn.makefile('r', encoding='utf-8', newline='\n')

    # 1) Esperar la llave pública del cliente
    pub_n = None
    pub_e = None
    try:
        linea = f.readline()
        if not linea:
            raise ValueError("Cliente cerró antes de enviar su llave pública.")
        pkt0 = json.loads(linea.strip())
        if pkt0.get("type") != "pubkey":
            raise ValueError("Primer paquete no es pubkey.")
        pub_n = int(pkt0["n"], 16)
        pub_e = int(pkt0["e"])
        print(f"[PUBKEY] Recibida llave pública de {addr}. e={pub_e}, n(bits)≈{pub_n.bit_length()}")
        conn.sendall(f"ID:{cid}\n".encode('utf-8'))
        conn.sendall(b"OK:PUBKEY\n")
    except Exception as e:
        print(f"[X] Error recibiendo pubkey de {addr}: {e}")
        try:
            f.close()
        except Exception:
            pass
        conn.close()
        return

    # 2) Recibir mensajes firmados
    try:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                paquete = json.loads(linea)
            except json.JSONDecodeError:
                print(f"[!] {addr} JSON inválido: {linea!r}")
                continue

            if paquete.get("type") != "data":
                print(f"[!] {addr} paquete no-data: {paquete}")
                continue

            msg = paquete.get("msg", "")
            sig = paquete.get("sig", "")
            if not msg or not sig:
                print(f"[!] {addr} paquete incompleto: {paquete}")
                continue

            if rsa_verify(sig, msg, pub_n, pub_e):
                print(f"[OK] Cliente #{cid} {addr}: {msg}")
            else:
                print(f"[X] Cliente #{cid} {addr}: Firma inválida. Mensaje rechazado.")
    except Exception as e:
        print(f"[ERROR] con {addr}: {e}")
    finally:
        try:
            f.close()
        except Exception:
            pass
        conn.close()
        print(f"Cliente #{cid} {addr} desconectado")

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