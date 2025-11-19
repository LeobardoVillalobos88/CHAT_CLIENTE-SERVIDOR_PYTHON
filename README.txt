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
Fecha: 19/11/2025  
Versión actual: 0.7

--------------------------------------------------------
DESCRIPCIÓN GENERAL
--------------------------------------------------------
Este proyecto implementa un sistema de comunicación en red tipo
chat cliente-servidor desarrollado en Python. El objetivo es
garantizar la integridad, autenticidad y confidencialidad de los
mensajes utilizando algoritmos criptográficos basados en SHA-256.

El desarrollo se realizó por versiones, iniciando con un chat
básico sin seguridad y avanzando hasta incorporar:

- Hashing simétrico HMAC-SHA256.
- Validación SHA-256 por mensaje.
- Canal cifrado SSL/TLS.
- Frontend web en tiempo real.
- Módulo de firma digital de archivos (txt, pdf, zip, etc.).

*Nota:* A partir de la versión 0.5, el cliente aprobó continuar
únicamente con la versión **simétrica**, al ser la más estable y
segura para los objetivos del proyecto.

--------------------------------------------------------
REQUISITOS
--------------------------------------------------------
- Python 3.8 o superior

Librerías principales (backend de chat + SSL):
- socket
- threading
- json
- hashlib
- hmac
- ssl
- python-dotenv (dotenv)
- cryptography (para certificados locales)
- time, uuid (utilizadas en versiones anteriores)

Librerías para firma digital de archivos:
- cryptography
- reportlab
- PyPDF2

Dependencias adicionales para el frontend web
(instalar con `pip install -r WebFrontend/requirements.txt`):
- Flask
- Flask-SocketIO
- python-dotenv
- eventlet / simple-websocket (según adaptador seleccionado)

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
  o ejecutar `python generar_certificado.py` (método alternativo).
- Asegurarse de colocar los archivos `cert.pem` y `key.pem` en la
  carpeta `Backend_Simetrico/` (según estructura actual).

Archivos:
- Backend_Simetrico/Servidor_Simetrico.py
- Backend_Simetrico/Cliente_Simetrico.py

MD5 (versión 0.5):
Servidor → 4b3eb687a8279e547f159e407498b35a
Cliente  → 5a563c59cc29e0e75f4ceb546fb5d087

--------------------------------------------------------

Versión 0.6 - (19/11/2025)
--------------------------
Se agrega un frontend web en tiempo real que funciona como puente entre los
clientes y el servidor simétrico.

CAMBIOS PRINCIPALES:
- Se creó el módulo `WebFrontend/` basado en Flask + Flask-SocketIO.
- Nueva interfaz cliente (`/`) que permite enviar mensajes web y solo ver el
  historial propio con confirmaciones de envío estilo WhatsApp.
- Nueva interfaz servidor (`/servidor`) en modo solo lectura para visualizar
  todos los mensajes recibidos desde cualquier cliente conectado.
- El backend web mantiene conexiones seguras TLS contra
  `Servidor_Simetrico.py` reutilizando las mismas claves y variables de entorno.
- Se reorganizó la lógica de confirmaciones y filtrado para evitar que los
  clientes web vean mensajes de otros usuarios.

REQUISITOS ADICIONALES:
- Instalar las dependencias listadas en `WebFrontend/requirements.txt`
  (Flask, Flask-SocketIO, python-dotenv, etc.).
- Ejecutar `python generar_certificado.py` (si aún no existen cert.pem/key.pem).
- Definir `.env` en la raíz con `HOST`, `PORT` y `SECRET_KEY`.

Archivos nuevos/destacados:
- `WebFrontend/app.py`
- `WebFrontend/templates/index.html`
- `WebFrontend/templates/servidor.html`
- `WebFrontend/static/css/style.css`
- `WebFrontend/static/css/servidor.css`

--------------------------------------------------------

Versión 0.7 - (19/11/2025)
--------------------------
Se implementa la **firma digital de archivos** desde el cliente y su
procesamiento en el servidor.

CAMBIOS PRINCIPALES DEL SERVIDOR:
- Se crea el módulo `FirmaDigital/firma_digital.py`:
  * Genera llaves RSA (carpeta `llaves_firma/`).
  * Permite firmar cualquier archivo (`firmar_archivo_generico`).
  * Para PDF genera un PDF adicional con la “Hoja de Firma Digital”
    y combina ambos en un solo archivo firmado (`firmar_pdf`).
- El servidor ahora:
  * Acepta paquetes JSON con `type = "archivo"`.
  * Verifica integridad con SHA-256 antes de aceptar el archivo.
  * Guarda los archivos en `archivos_recibidos/`.
  * Si es PDF, crea:
       - `archivos_firmados/firmado_<nombre>.pdf`
       - `archivos_firmados/<nombre>.pdf.sig`
    incluyendo la hoja de firma digital al final.
  * Si no es PDF, genera únicamente el archivo `.sig` con la firma.

CAMBIOS PRINCIPALES DEL CLIENTE GUI:
- `Cliente_Simetrico_GUI.py` incorpora un botón:
  **"Enviar archivo para firma"**
- Flujo:
  1. El usuario selecciona un archivo (txt, pdf, zip, etc.).
  2. El cliente:
     - Lee el archivo en binario.
     - Calcula SHA-256 de los bytes.
     - Codifica el contenido en Base64.
     - Envía un paquete:
       {
         "type": "archivo",
         "nombre": "<archivo>",
         "data": "<base64>",
         "sha": "<sha256_hex>"
       }
  3. El servidor valida, guarda y firma el documento.
- En el área de chat se muestra un mensaje de sistema:
  `[SISTEMA] Documento enviado para firma: <archivo> (X.Y KB)`

CARPETAS RELACIONADAS:
- `archivos_recibidos/`    → Archivos originales enviados por los clientes.
- `llaves_firma/`          → Llaves RSA usadas para firmar.
- `archivos_firmados/`     → PDFs finales con hoja de firma y archivos `.sig`.

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

Para la firma digital de archivos:

   >>> pip install cryptography reportlab PyPDF2

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

- **RSA + SHA-256 (firma digital de archivos):**
  Firma documentos para que el cliente pueda comprobar que un archivo
  no ha sido modificado desde que fue firmado por el servidor.

--------------------------------------------------------
CÓMO EJECUTAR (RESUMEN)
--------------------------------------------------------
1. Preparar el entorno (solo primera vez):
   - Crear el archivo `.env` en la raíz con `HOST`, `PORT`, `SECRET_KEY`.
   - Generar certificados ejecutando `python generar_certificado.py`.
   - Instalar dependencias del frontend web:
       >>> cd WebFrontend
       >>> pip install -r requirements.txt
   - Instalar dependencias de firma:
       >>> pip install cryptography reportlab PyPDF2 python-dotenv

2. Iniciar el servidor principal (terminal 1):
   >>> cd Backend_Simetrico
   >>> python Servidor_Simetrico.py

3. (Opcional) Iniciar el frontend web (terminal 2):
   >>> cd WebFrontend
   >>> python app.py
   - Cliente web:    http://localhost:8080
   - Vista servidor: http://localhost:8080/servidor

4. Iniciar cliente de escritorio (GUI) (terminal 3):
   >>> cd Backend_Simetrico
   >>> python Cliente_Simetrico_GUI.py

5. Uso de firma digital:
   - En la ventana GUI, hacer clic en **"Enviar archivo para firma"**.
   - Seleccionar un archivo txt/pdf/zip.
   - Verificar en la consola del servidor los mensajes:
       * Archivo recibido y guardado.
       * Ruta de archivo firmado (`archivos_firmados/`).
       * Ruta de archivo `.sig`.
   - Para PDF, abrir el `firmado_<nombre>.pdf` y revisar la
     “Hoja de Firma Digital” añadida al final.

6. (Opcional) Cliente CLI:
   >>> python Cliente_Simetrico.py
   Este cliente envía solo mensajes de texto, pero comparte el mismo
   servidor y canal seguro.

--------------------------------------------------------
FIN DEL DOCUMENTO
--------------------------------------------------------