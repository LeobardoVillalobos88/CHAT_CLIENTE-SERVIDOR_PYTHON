import base64
from FirmaDigital.firma_digital import sha256_bytes, verificar_firma_bytes

def verificar_firma(archivo_pdf: str, archivo_sig: str):
    try:
        with open(archivo_pdf, "rb") as f:
            contenido = f.read()
        hash_local = sha256_bytes(contenido)

        with open(archivo_sig, "rb") as f:
            firma = base64.b64decode(f.read())

        ok = verificar_firma_bytes(contenido, firma)
        if ok:
            print("\n🔒 FIRMA DIGITAL VÁLIDA")
            print("→ El archivo NO ha sido modificado")
            print(f"→ Hash: {hash_local}")
        else:
            print("\n❌ FIRMA NO VÁLIDA")
            print("→ El archivo fue modificado o la firma corresponde a otro archivo")

    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    print("=== VERIFICADOR DE FIRMA DIGITAL ===")
    archivo_pdf = input("Ruta del PDF a validar: ")
    archivo_sig = input("Ruta del archivo .sig: ")
    verificar_firma(archivo_pdf, archivo_sig)