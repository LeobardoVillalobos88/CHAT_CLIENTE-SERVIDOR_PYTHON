import socket
import json
import hashlib
import random

HOST = '127.0.0.1'
PORT = 5000

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No existe inverso modular")
    return x % m

def miller_rabin(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def rand_odd(bits):
    x = random.getrandbits(bits)
    x |= 1
    x |= (1 << (bits - 1))
    return x

def gen_prime(bits):
    while True:
        p = rand_odd(bits)
        if miller_rabin(p):
            return p

def gen_rsa_keypair(bits=512, e=65537):
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while p == q:
        q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    if phi % e == 0:
        return gen_rsa_keypair(bits, e)
    d = modinv(e, phi)
    return (n, e), (n, d)

def sha256_int(msg: str) -> int:
    h = hashlib.sha256(msg.encode('utf-8')).hexdigest()
    return int(h, 16)

def sha256_hex(texto: str) -> str:  # SHA simple (checksum)
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def rsa_sign(msg: str, priv_n: int, priv_d: int) -> str:
    h = sha256_int(msg) % priv_n
    sig = pow(h, priv_d, priv_n)
    return hex(sig)[2:]

def recibir_linea(sock: socket.socket) -> str:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(64)
        if not chunk:
            break
        buf += chunk
    return buf.decode('utf-8', errors='ignore').strip()

def main():
    print("Generando par de llaves RSA (demo)…")
    (pub_n, pub_e), (priv_n, priv_d) = gen_rsa_keypair(bits=512, e=65537)
    print(f"Listo. n(bits)≈{pub_n.bit_length()}, e={pub_e}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    f = sock.makefile('w', encoding='utf-8', newline='\n')

    # 1) Enviar llave pública al servidor
    pubpkt = {"type": "pubkey", "n": hex(pub_n)[2:], "e": pub_e}
    f.write(json.dumps(pubpkt) + "\n")
    f.flush()

    etiqueta = "Cliente"
    try:
        linea1 = recibir_linea(sock)
        if linea1.startswith("ID:"):
            try:
                cid = int(linea1.split(":", 1)[1])
                etiqueta = f"Cliente {cid}"
            except Exception:
                pass
        linea2 = recibir_linea(sock)  # OK:PUBKEY
    except Exception:
        pass

    print("Escribe (salir) para terminar de chatear: ")
    try:
        while True:
            msg = input(f"{etiqueta}: ")
            if msg.lower() == "salir":
                break
            firma_hex = rsa_sign(msg, priv_n, priv_d)
            data = {
                "type": "data",
                "msg": msg,
                "sha": sha256_hex(msg),   # SHA por mensaje
                "sig": firma_hex          # Firma RSA como antes
            }
            f.write(json.dumps(data) + "\n")
            f.flush()
    finally:
        try:
            f.close()
        except Exception:
            pass
        sock.close()

if __name__ == "__main__":
    main()