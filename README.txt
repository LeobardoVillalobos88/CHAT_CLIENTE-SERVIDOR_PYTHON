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
Fecha: 12/10/2025
Versión actual: 0.4

--------------------------------------------------------
DESCRIPCIÓN GENERAL
--------------------------------------------------------
Este proyecto implementa un sistema de comunicación en red tipo
chat cliente-servidor desarrollado en Python. El objetivo es
garantizar la integridad y autenticidad de los mensajes utilizando
algoritmos criptográficos basados en SHA-256.

El desarrollo se realizó por versiones, iniciando con un chat
básico sin seguridad y avanzando hasta incorporar mecanismos
de hashing simétrico (HMAC) y asimétrico (RSA).

--------------------------------------------------------
REQUISITOS
--------------------------------------------------------
- Python 3.8 o superior
- Librerías estándar (no se requiere instalación externa):
  * socket
  * threading
  * json
  * hashlib
  * random

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

- En el cliente, cada mensaje se procesa con SHA-256 para generar su hash.
- El servidor recalcula el hash del mensaje recibido y verifica su coincidencia.
- Si el valor SHA coincide, el mensaje se acepta; si no, se descarta.
- En el modelo asimétrico se mantienen además las firmas RSA-SHA256 
  para verificar la autenticidad del remitente.

Archivos:
- Servidor_Simetrico.py / Cliente_Simetrico.py
- Servidor_Asimetrico.py / Cliente_Asimetrico.py

MD5:
Servidor_Simetrico → f6181a5730f492284903d7747f347522
Cliente_Simetrico  → 467069cd0af43103cab6b2475cea7f30
Servidor_Asimetrico → 15740ed7bb7eb9e6c864f01ea0947316 
Cliente_Asimetrico  → b16e300ad7643410e5d4e30914f2479e

--------------------------------------------------------
CIFRADO / HASH UTILIZADO
--------------------------------------------------------
- SHA-256 (Checksum por mensaje)
  * Garantiza integridad: el servidor comprueba que los datos no 
    hayan sido modificados durante la transmisión.

- RSA-SHA256 (firma digital)
  * Asegura autenticidad: solo el cliente con la clave privada 
    puede generar una firma válida.

- HMAC-SHA256 (clave compartida)
  * Mantiene integridad y autenticación simétrica.

--------------------------------------------------------
CÓMO EJECUTAR
--------------------------------------------------------
1. Ejecutar primero el servidor (según la versión deseada):
   >>> python Servidor_Simetrico.py
   o bien:
   >>> python Servidor_Asimetrico.py

2. Ejecutar el cliente correspondiente:
   >>> python Cliente_Simetrico.py
   o bien:
   >>> python Cliente_Asimetrico.py

3. Escribir mensajes y presionar ENTER para enviarlos.
   El servidor mostrará si el SHA y/o la firma son válidos.

--------------------------------------------------------
FIN DEL DOCUMENTO
--------------------------------------------------------