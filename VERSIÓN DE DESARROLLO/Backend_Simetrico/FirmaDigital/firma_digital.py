# firma_digital.py
# Módulo de firma digital para archivos (txt, pdf, zip, etc.)
# Para PDF, genera además una "Hoja de Firma Digital" como última página.

import os
import base64
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from PyPDF2 import PdfMerger, PdfReader, PdfWriter


# ===============================
# CONFIGURACIÓN DE RUTAS
# ===============================
CARPETA_LLAVES = "llaves_firma"
CARPETA_FIRMADOS = "archivos_firmados"

os.makedirs(CARPETA_LLAVES, exist_ok=True)
os.makedirs(CARPETA_FIRMADOS, exist_ok=True)


# ===============================
# LLAVES RSA PARA FIRMA DIGITAL
# ===============================
PRIVATE_KEY_PATH = os.path.join(CARPETA_LLAVES, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(CARPETA_LLAVES, "public_key.pem")


def generar_llaves():
    """Genera un par de llaves RSA y las guarda en PEM si no existen."""
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        print("🔑 Llaves de firma ya existen. No se regeneran.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"🔑 Llaves generadas en: {CARPETA_LLAVES}/private_key.pem y public_key.pem")


def _cargar_llave_privada():
    if not os.path.exists(PRIVATE_KEY_PATH):
        generar_llaves()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _cargar_llave_publica():
    if not os.path.exists(PUBLIC_KEY_PATH):
        raise FileNotFoundError("No se encontró la llave pública de firma.")
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ===============================
# AUXILIARES DE HASH Y FIRMA
# ===============================
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def firmar_bytes(data: bytes) -> bytes:
    """Firma bytes con la llave privada RSA y SHA-256."""
    private_key = _cargar_llave_privada()
    firma = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return firma


def verificar_firma_bytes(data: bytes, firma: bytes) -> bool:
    """Verifica una firma sobre bytes usando la llave pública."""
    public_key = _cargar_llave_publica()
    try:
        public_key.verify(
            firma,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ===============================
# FIRMA DE ARCHIVOS GENÉRICA
# ===============================
def firmar_archivo_generico(ruta_archivo: str, cliente_id: int = None):
    """
    Firma cualquier tipo de archivo (txt, zip, pdf, etc.).
    Genera un archivo .sig con la firma en base64.
    """
    with open(ruta_archivo, "rb") as f:
        contenido = f.read()

    hash_hex = sha256_bytes(contenido)
    firma = firmar_bytes(contenido)
    firma_b64 = base64.b64encode(firma)

    ruta_sig = ruta_archivo + ".sig"
    with open(ruta_sig, "wb") as f:
        f.write(firma_b64)

    info = {
        "archivo": ruta_archivo,
        "hash": hash_hex,
        "cliente_id": cliente_id,
        "firma_sig": ruta_sig,
    }

    print(f"✅ Archivo firmado (genérico): {ruta_sig}")
    return ruta_sig, info


# ===============================
# HOJA DE FIRMA DIGITAL PARA PDF
# ===============================
def _crear_hoja_firma_pdf(ruta_salida: str, nombre_archivo: str, hash_hex: str, cliente_id: int | None):
    """Crea un PDF de una página con los datos de la firma ('Hoja de Firma Digital')."""
    c = canvas.Canvas(ruta_salida, pagesize=A4)
    ancho, alto = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, alto - 80, "HOJA DE FIRMA DIGITAL")

    c.setFont("Helvetica", 11)
    y = alto - 120
    c.drawString(50, y, f"Documento firmado por el Servidor Seguro")
    y -= 20
    c.drawString(50, y, f"Sistema: Chat Cliente-Servidor SegInfo (v0.6)")
    y -= 30
    c.drawString(50, y, f"Nombre del archivo: {nombre_archivo}")
    y -= 20
    if cliente_id is not None:
        c.drawString(50, y, f"Cliente solicitante: Cliente #{cliente_id}")
        y -= 20
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(50, y, f"Fecha de firma: {fecha}")
    y -= 30
    c.drawString(50, y, "Hash SHA-256 del archivo original:")
    y -= 20

    # Imprimir el hash en varias líneas si está muy largo
    for i in range(0, len(hash_hex), 64):
        c.drawString(70, y, hash_hex[i:i+64])
        y -= 15

    y -= 20
    c.drawString(50, y, "Canal de transmisión: SSL/TLS")
    y -= 20
    c.drawString(50, y, "Validación adicional: HMAC-SHA256 (mensajes de chat)")
    y -= 40

    c.setFont("Helvetica-Oblique", 10)
    c.drawString(50, y, "La firma es válida únicamente si el hash coincide con el archivo original.")
    y -= 15
    c.drawString(50, y, "No modificar este documento. Cualquier cambio invalida la firma digital.")

    c.showPage()
    c.save()


def firmar_pdf(ruta_pdf: str, cliente_id: int = None):
    if not os.path.exists(ruta_pdf):
        raise FileNotFoundError(f"No existe el PDF: {ruta_pdf}")

    with open(ruta_pdf, "rb") as f:
        contenido = f.read()

    hash_hex = sha256_bytes(contenido)
    firma = firmar_bytes(contenido)
    firma_b64 = base64.b64encode(firma)

    nombre_base = os.path.basename(ruta_pdf)
    ruta_sig = os.path.join(CARPETA_FIRMADOS, nombre_base + ".sig")
    with open(ruta_sig, "wb") as f:
        f.write(firma_b64)

    hoja_firma_temp = "hoja_firma_temp.pdf"
    _crear_hoja_firma_pdf(hoja_firma_temp, nombre_base, hash_hex, cliente_id)

    ruta_pdf_firmado = os.path.join(CARPETA_FIRMADOS, f"firmado_{nombre_base}")

    # 🔄 Nueva forma de combinar PDF + hoja
    merger = PdfMerger()
    merger.append(ruta_pdf)
    merger.append(hoja_firma_temp)
    with open(ruta_pdf_firmado, "wb") as f:
        merger.write(f)
    merger.close()

    try:
        os.remove(hoja_firma_temp)
    except:
        pass

    print(f"✅ PDF firmado correctamente → {ruta_pdf_firmado}")
    print(f"📄 Firma en Base64 → {ruta_sig}")

    return ruta_pdf_firmado, ruta_sig, {
        "archivo_original": ruta_pdf,
        "archivo_firmado": ruta_pdf_firmado,
        "hash": hash_hex,
        "cliente_id": cliente_id,
        "firma_sig": ruta_sig,
    }


# DEMO manual (opcional)
if __name__ == "__main__":
    print("=== DEMO FIRMA DIGITAL ===")
    print("1) Generar llaves")
    print("2) Firmar archivo genérico")
    print("3) Firmar PDF")
    op = input("Opción: ")

    if op == "1":
        generar_llaves()
    elif op == "2":
        ruta = input("Ruta del archivo a firmar: ")
        firmar_archivo_generico(ruta)
    elif op == "3":
        ruta = input("Ruta del PDF a firmar: ")
        firmar_pdf(ruta, cliente_id=1)