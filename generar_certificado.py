from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

# Directorio donde se guardarán los certificados (carpeta Simetrico)
CERT_DIR = "Simetrico"
CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE = os.path.join(CERT_DIR, "key.pem")

# Crear directorio si no existe
if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)
    print(f"📁 Directorio '{CERT_DIR}' creado")

# Verificar si ya existen los certificados
if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
    respuesta = input(f"⚠️  Los certificados ya existen en {CERT_DIR}/. ¿Deseas regenerarlos? (s/n): ")
    if respuesta.lower() != 's':
        print("❌ Operación cancelada. Se mantienen los certificados existentes.")
        exit(0)

print("🔐 Generando certificados SSL/TLS...")

# Generar clave privada
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Guardar la clave privada
with open(KEY_FILE, "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Crear certificado autofirmado
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Morelos"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "UTZ"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ChatSeguridad"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)

# Guardar el certificado
with open(CERT_FILE, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"✅ Certificado y clave generados exitosamente:")
print(f"   📄 {CERT_FILE}")
print(f"   🔑 {KEY_FILE}")
print(f"\n💡 Estos certificados son válidos por 365 días.")
print(f"💡 Ahora puedes ejecutar el servidor desde la carpeta '{CERT_DIR}/'")