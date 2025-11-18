========================================================
README - Chat Cliente-Servidor con Hashing SHA-256
========================================================

Autores:  
Garduño Cruz Sergio Jhoel  
Bertadillo Villalobos Leobardo Daniel  
Torres Galván Alejandro Aldahir  
Nieto Ramírez Caleb Isai  
Paredes Domínguez Jassiel

Materia: Seguridad Informática  
Fecha: 02/11/2025  
Versión actual: 0.5

--------------------------------------------------------
DESCRIPCIÓN GENERAL
--------------------------------------------------------
Este proyecto implementa un sistema de comunicación en red tipo
chat cliente-servidor desarrollado en Python. El objetivo es
garantizar la integridad, autenticidad y confidencialidad de los
mensajes utilizando algoritmos criptográficos basados en SHA-256.

El desarrollo se realizó por versiones, iniciando con un chat
básico sin seguridad y avanzando hasta incorporar mecanismos de
hashing simétrico (HMAC), validación SHA-256 por mensaje y, en
versiones previas, un modelo asimétrico (RSA) para demostración.

*Nota:* A partir de la versión 0.5, el cliente aprobó continuar
únicamente con la versión **simétrica**, al ser la más estable y
segura para los objetivos del proyecto.

--------------------------------------------------------
REQUISITOS
--------------------------------------------------------
- Python 3.8 o superior
- Librerías estándar (no requiere instalación externa):
  * socket
  * threading
  * json
  * hashlib
  * hmac
  * ssl
  * dotenv (para leer variables de entorno)
  * cryptography (para generar certificados locales)
  * time, uuid (utilizadas en versiones anteriores)

--------------------------------------------------------
VERSIONES Y CAMBIOS
--------------------------------------------------------

Versión 0.1 - (24/09/2025)
--------------------------
Creación inicial del sistema de chat cliente-servidor.
- Comunicación TCP/IP básica.
- Sin mecanismos de seguridad.

Archivos:
- Servidor.py
- Cliente.py

--------------------------------------------------------

Versión 0.2 - (05/10/2025)
--------------------------
Implementación del protocolo de hashing simétrico HMAC-SHA256.
- Se agregó una clave secreta compartida (SECRET_KEY).
- Los mensajes incluyen un campo “hmac” para verificación.
- Se utiliza compare_digest() para evitar ataques de tiempo.

Archivos:
- Servidor_Simetrico.py
- Cliente_Simetrico.py

MD5:
Servidor → 71980e9697b876ac8c33b1ba3532c860
Cliente  → 8808782d9cfa80ba41fa60d81ef631b4

--------------------------------------------------------

Versión 0.3 - (05/10/2025)
--------------------------
Implementación de hashing asimétrico RSA-SHA256.
- Cada cliente genera un par de llaves (pública y privada).
- El servidor valida las firmas con la llave pública del cliente.
- Se añadió soporte multi-cliente mediante hilos (threading).
- Se asigna un número de cliente (Cliente 1, Cliente 2, etc.).

Archivos:
- Servidor_Asimetrico.py
- Cliente_Asimetrico.py

MD5:
Servidor → 15740ed7bb7eb9e6c864f01ea0947316
Cliente  → 293e90f22c2de0dc11b30d6b223acb20

--------------------------------------------------------

Versión 0.4 - (19/10/2025)
--------------------------
Se agrega validación de integridad SHA-256 por mensaje (checksum)
en ambos modelos: simétrico y asimétrico.

- El cliente calcula el hash SHA-256 por mensaje.
- El servidor recalcula el hash y compara resultados.
- Si coincide, el mensaje se acepta; si no, se descarta.
- En el modelo asimétrico, se mantiene la firma RSA-SHA256.

Archivos:
- Servidor_Simetrico.py / Cliente_Simetrico.py  
- Servidor_Asimetrico.py / Cliente_Asimetrico.py

MD5:
Servidor_Simetrico → f6181a5730f492284903d7747f347522
Cliente_Simetrico  → 467069cd0af43103cab6b2475cea7f30
Servidor_Asimetrico → 15740ed7bb7eb9e6c864f01ea0947316
Cliente_Asimetrico  → b16e300ad7643410e5d4e30914f2479e

--------------------------------------------------------

Versión 0.5 - (02/11/2025)
--------------------------
Se elimina el uso de claves hardcodeadas y se agrega soporte SSL/TLS.

CAMBIOS PRINCIPALES:
- La clave secreta usada para HMAC-SHA256 ahora se carga desde una
  variable de entorno llamada SECRET_KEY.
- Se creó un archivo .env con las variables:
    SECRET_KEY=SergioLeobardoJassielCalebAlejandro  
    HOST=127.0.0.1  
    PORT=5000
- Se integra la librería 'ssl' para permitir conexiones cifradas TLS.
- El servidor genera un contexto SSL con certificado y clave privada.
- El cliente utiliza el mismo contexto para autenticarse y verificar
  la conexión.
- Toda la comunicación entre cliente y servidor ahora viaja cifrada.

REQUISITOS ADICIONALES:
- Crear un archivo `.env` en la raíz del proyecto.
- Generar certificados autofirmados (para entorno local) con:
  >>> openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
- Asegurarse de colocar los archivos `cert.pem` y `key.pem` en la misma
  carpeta que el servidor.

Archivos:
- Servidor_Simetrico.py
- Cliente_Simetrico.py

MD5:
Servidor → 4b3eb687a8279e547f159e407498b35a
Cliente  → 5a563c59cc29e0e75f4ceb546fb5d087

--------------------------------------------------------
GENERACIÓN DEL CERTIFICADO (MÉTODO ALTERNATIVO)
--------------------------------------------------------
Si el comando `openssl` no está disponible en el sistema, es posible
crear los certificados de forma automática utilizando Python:

1. Instalar la librería `cryptography`:
   >>> pip install cryptography

2. Ejecutar el script auxiliar `generar_certificado.py` incluido
   en el proyecto. Este script genera automáticamente los archivos:
   - cert.pem  (certificado autofirmado)
   - key.pem   (clave privada)

3. Al ejecutarse correctamente, mostrará el mensaje:
   Certificado y clave generados: cert.pem / key.pem

4. Una vez generados, no es necesario volver a ejecutar el script
   a menos que se eliminen o caduquen los certificados.

--------------------------------------------------------
INSTALACIÓN DE DEPENDENCIAS ADICIONALES
--------------------------------------------------------
Para leer las variables de entorno del archivo `.env`, se requiere
instalar la librería `python-dotenv`:

   >>> pip install python-dotenv

Ambas librerías (`cryptography` y `python-dotenv`) son necesarias
solo para el entorno de desarrollo y no afectan la lógica del chat.

--------------------------------------------------------
NOTA
--------------------------------------------------------
Los certificados `cert.pem` y `key.pem` pueden generarse mediante el
comando `openssl` o con el script `generar_certificado.py`.  
Ambos métodos producen certificados X.509 válidos y compatibles con
el módulo `ssl` de Python, garantizando la comunicación cifrada TLS
entre cliente y servidor.  
El método con `cryptography` es ideal para entornos Windows donde
OpenSSL no está instalado, manteniendo el mismo nivel de seguridad.

--------------------------------------------------------
CIFRADO / HASH UTILIZADO
--------------------------------------------------------
- **SHA-256 (Checksum por mensaje):**
  Garantiza la integridad del mensaje al verificar que los datos no se
  hayan modificado durante la transmisión.

- **HMAC-SHA256 (clave compartida):**
  Asegura autenticidad y verificación del origen utilizando la clave
  almacenada en variable de entorno.

- **SSL/TLS:**
  Cifra completamente el canal de comunicación, protegiendo los datos
  frente a intercepción o manipulación en tránsito.

--------------------------------------------------------
CÓMO EJECUTAR
--------------------------------------------------------
1. Ejecutar primero el servidor:
   >>> python Servidor_Simetrico.py

2. Ejecutar el cliente:
   >>> python Cliente_Simetrico.py

3. Escribir mensajes y presionar ENTER para enviarlos.
   El servidor mostrará si el SHA y/o el HMAC son válidos.

4. Verificar que la conexión se establezca en modo seguro (SSL/TLS).

--------------------------------------------------------
FIN DEL DOCUMENTO
--------------------------------------------------------