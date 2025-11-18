"""
Servidor web intermedio para el chat seguro
Actúa como puente entre el frontend web y el servidor de chat existente
"""
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, disconnect
import socket
import ssl
import hmac
import hashlib
import json
import os
import threading
from dotenv import load_dotenv

# CARGA DE VARIABLES DE ENTORNO
load_dotenv()
CHAT_HOST = os.getenv("HOST", "127.0.0.1")
CHAT_PORT = int(os.getenv("PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "ClavePorDefecto").encode("utf-8")

# CONFIGURACIÓN SSL/TLS para conectar al servidor de chat
ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'chat-secreto-web-2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Almacenar conexiones de clientes web
clientes_web = {}

# FUNCIONES AUXILIARES
def firmar(msg: str) -> str:
    return hmac.new(SECRET_KEY, msg.encode('utf-8'), hashlib.sha256).hexdigest()

def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode('utf-8')).hexdigest()

def recibir_id(sock: ssl.SSLSocket) -> int:
    buffer = b""
    while b"\n" not in buffer:
        chunk = sock.recv(64)
        if not chunk:
            break
        buffer += chunk
    try:
        linea = buffer.decode('utf-8', errors='ignore').strip()
        if linea.startswith("ID:"):
            return int(linea.split(":", 1)[1])
    except Exception:
        pass
    return -1

def recibir_mensajes_chat(session_id):
    """Hilo para recibir mensajes del servidor de chat y reenviarlos al frontend"""
    if session_id not in clientes_web:
        return
    
    cliente = clientes_web[session_id]
    file_reader = cliente.get('file_reader')
    if not file_reader:
        return
    
    try:
        for linea in file_reader:
            if session_id not in clientes_web:
                break
            linea = linea.strip()
            if not linea:
                continue
            try:
                paquete = json.loads(linea)
                if paquete.get("type") == "mensaje":
                    cliente_id = paquete.get("cliente_id", 0)
                    mensaje = paquete.get("mensaje", "")
                    timestamp = paquete.get("timestamp", "")
                    
                    # Solo reenviar si no es nuestro propio mensaje
                    if cliente_id != cliente['cid']:
                        socketio.emit('mensaje_recibido', {
                            'cliente_id': cliente_id,
                            'etiqueta': f"Cliente {cliente_id}",
                            'mensaje': mensaje,
                            'timestamp': timestamp
                        }, room=session_id)
            except json.JSONDecodeError:
                continue
    except Exception as e:
        if session_id in clientes_web:
            socketio.emit('error', {'mensaje': f"Error al recibir: {str(e)}"}, room=session_id)
            desconectar_del_servidor_chat(session_id)

def conectar_al_servidor_chat(session_id):
    """Conecta al servidor de chat y mantiene la conexión"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = ssl_context.wrap_socket(sock, server_hostname=CHAT_HOST)
        conn.connect((CHAT_HOST, CHAT_PORT))
        
        cid = recibir_id(conn)
        file_writer = conn.makefile('w', encoding='utf-8', newline='\n')
        file_reader = conn.makefile('r', encoding='utf-8', newline='\n')
        
        clientes_web[session_id] = {
            'conn': conn,
            'file_writer': file_writer,
            'file_reader': file_reader,
            'cid': cid,
            'etiqueta': f"Cliente {cid}" if cid > 0 else "Cliente"
        }
        
        # Iniciar hilo para recibir mensajes
        hilo_receptor = threading.Thread(
            target=recibir_mensajes_chat, 
            args=(session_id,), 
            daemon=True
        )
        hilo_receptor.start()
        
        socketio.emit('conectado', {
            'id': cid,
            'etiqueta': clientes_web[session_id]['etiqueta']
        }, room=session_id)
        
        return True
    except Exception as e:
        socketio.emit('error', {'mensaje': f"Error de conexión: {str(e)}"}, room=session_id)
        return False

def desconectar_del_servidor_chat(session_id):
    """Desconecta del servidor de chat"""
    if session_id in clientes_web:
        try:
            cliente = clientes_web[session_id]
            if 'file_reader' in cliente:
                cliente['file_reader'].close()
            if 'file_writer' in cliente:
                cliente['file_writer'].close()
            if 'conn' in cliente:
                cliente['conn'].close()
        except Exception:
            pass
        del clientes_web[session_id]

# RUTAS WEB
@app.route('/')
def index():
    return render_template('index.html')

# WEBSOCKET EVENTS
@socketio.on('connect')
def handle_connect():
    """Cuando un cliente web se conecta"""
    session_id = request.sid
    print(f"[WEB] Cliente conectado: {session_id}")
    
    # Conectar al servidor de chat
    if conectar_al_servidor_chat(session_id):
        emit('estado', {'conectado': True})
    else:
        emit('estado', {'conectado': False})

@socketio.on('disconnect')
def handle_disconnect():
    """Cuando un cliente web se desconecta"""
    session_id = request.sid
    print(f"[WEB] Cliente desconectado: {session_id}")
    desconectar_del_servidor_chat(session_id)

@socketio.on('enviar_mensaje')
def handle_mensaje(data):
    """Recibe un mensaje del frontend y lo envía al servidor de chat"""
    session_id = request.sid
    
    if session_id not in clientes_web:
        emit('error', {'mensaje': 'No conectado al servidor de chat'})
        return
    
    mensaje = data.get('mensaje', '').strip()
    if not mensaje:
        return
    
    try:
        # Crear paquete con seguridad
        paquete = {
            "msg": mensaje,
            "sha": sha256_hex(mensaje),
            "hmac": firmar(mensaje)
        }
        
        # Enviar al servidor de chat
        cliente = clientes_web[session_id]
        cliente['file_writer'].write(json.dumps(paquete) + "\n")
        cliente['file_writer'].flush()
        
        # Confirmar al frontend
        emit('mensaje_enviado', {
            'mensaje': mensaje,
            'etiqueta': cliente['etiqueta']
        })
        
    except Exception as e:
        emit('error', {'mensaje': f"Error al enviar: {str(e)}"})
        desconectar_del_servidor_chat(session_id)

if __name__ == '__main__':
    print("=" * 50)
    print("Servidor Web iniciado")
    print(f"Frontend disponible en: http://localhost:8080")
    print(f"Conectando al servidor de chat en: {CHAT_HOST}:{CHAT_PORT}")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)

