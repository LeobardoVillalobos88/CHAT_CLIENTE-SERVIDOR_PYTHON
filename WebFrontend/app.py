"""
Servidor web intermedio para el chat seguro
Actúa como puente entre el frontend web y el servidor de chat existente
"""
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit, disconnect
import socket
import ssl
import hmac
import hashlib
import json
import os
import threading
import base64
import tempfile
from datetime import datetime
from dotenv import load_dotenv

# Importar funciones de firma digital
import sys
# Obtener la ruta del directorio del proyecto (raíz)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, 'Backend_Simetrico')
sys.path.insert(0, BACKEND_DIR)
from FirmaDigital.firma_digital import (
    firmar_pdf, 
    firmar_archivo_generico, 
    sha256_bytes, 
    generar_llaves,
    verificar_firma_bytes
)

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
    modo_servidor = cliente.get('modo_servidor', False)
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
                    
                    if modo_servidor:
                        # Modo servidor: recibir TODOS los mensajes (incluyendo del remitente)
                        socketio.emit('mensaje_recibido', {
                            'cliente_id': cliente_id,
                            'etiqueta': f"Cliente {cliente_id}",
                            'mensaje': mensaje,
                            'timestamp': timestamp
                        }, room=session_id)
                    else:
                        # Modo cliente: solo recibir mensajes de otros clientes (no propios)
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

def conectar_al_servidor_chat(session_id, modo_servidor=False):
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
            'etiqueta': f"Cliente {cid}" if cid > 0 else "Cliente",
            'modo_servidor': modo_servidor
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

@app.route('/servidor')
def servidor():
    return render_template('servidor.html')

# RUTA PARA FIRMA DIGITAL
@app.route('/firmar_archivo', methods=['POST'])
def firmar_archivo():
    """Recibe un archivo del frontend, lo firma y devuelve los resultados"""
    try:
        if 'archivo' not in request.files:
            return jsonify({'error': 'No se proporcionó ningún archivo'}), 400
        
        archivo = request.files['archivo']
        if archivo.filename == '':
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
        
        # Leer el archivo
        contenido = archivo.read()
        nombre_original = archivo.filename
        
        # Guardar temporalmente para firmar
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(nombre_original)[1]) as temp_file:
            temp_file.write(contenido)
            temp_path = temp_file.name
        
        try:
            # Asegurar que existan las llaves
            generar_llaves()
            
            # Firmar según el tipo
            es_pdf = nombre_original.lower().endswith('.pdf')
            
            if es_pdf:
                ruta_pdf_firmado, ruta_sig, info = firmar_pdf(temp_path, cliente_id=None)
                
                # Leer archivos firmados
                with open(ruta_pdf_firmado, 'rb') as f:
                    pdf_firmado_data = f.read()
                
                with open(ruta_sig, 'rb') as f:
                    firma_data = f.read()
                
                # Limpiar archivos temporales del servidor
                try:
                    os.remove(ruta_pdf_firmado)
                    os.remove(ruta_sig)
                except:
                    pass
                
                return jsonify({
                    'exito': True,
                    'nombre_original': nombre_original,
                    'archivo_firmado': base64.b64encode(pdf_firmado_data).decode('utf-8'),
                    'firma': base64.b64encode(firma_data).decode('utf-8'),
                    'hash': info.get('hash', ''),
                    'tipo': 'pdf',
                    'nombre_firmado': f'firmado_{nombre_original}',
                    'nombre_firma': f'{nombre_original}.sig'
                })
            else:
                ruta_sig, info = firmar_archivo_generico(temp_path, cliente_id=None)
                
                # Leer firma
                with open(ruta_sig, 'rb') as f:
                    firma_data = f.read()
                
                # Limpiar archivo temporal
                try:
                    os.remove(ruta_sig)
                except:
                    pass
                
                return jsonify({
                    'exito': True,
                    'nombre_original': nombre_original,
                    'archivo_original': base64.b64encode(contenido).decode('utf-8'),
                    'firma': base64.b64encode(firma_data).decode('utf-8'),
                    'hash': info.get('hash', ''),
                    'tipo': 'generico',
                    'nombre_firma': f'{nombre_original}.sig'
                })
        finally:
            # Limpiar archivo temporal
            try:
                os.remove(temp_path)
            except:
                pass
                
    except Exception as e:
        return jsonify({'error': f'Error al firmar archivo: {str(e)}'}), 500

# RUTA PARA VERIFICAR FIRMA DIGITAL
@app.route('/verificar_firma', methods=['POST'])
def verificar_firma():
    """Recibe un archivo y su firma, y verifica que la firma sea válida"""
    try:
        if 'archivo' not in request.files or 'firma' not in request.files:
            return jsonify({'error': 'Debes proporcionar tanto el archivo como la firma (.sig)'}), 400
        
        archivo = request.files['archivo']
        firma_file = request.files['firma']
        
        if archivo.filename == '' or firma_file.filename == '':
            return jsonify({'error': 'Debes seleccionar ambos archivos'}), 400
        
        # Leer el archivo y la firma
        contenido_archivo = archivo.read()
        contenido_firma = firma_file.read()
        
        # Decodificar la firma (está en base64)
        try:
            firma_bytes = base64.b64decode(contenido_firma)
        except Exception:
            return jsonify({'error': 'El archivo de firma no está en formato base64 válido'}), 400
        
        # Calcular hash del archivo
        hash_archivo = sha256_bytes(contenido_archivo)
        
        # Verificar la firma
        firma_valida = verificar_firma_bytes(contenido_archivo, firma_bytes)
        
        return jsonify({
            'exito': True,
            'firma_valida': firma_valida,
            'hash': hash_archivo,
            'mensaje': '✅ FIRMA DIGITAL VÁLIDA - El archivo NO ha sido modificado' if firma_valida 
                      else '❌ FIRMA NO VÁLIDA - El archivo fue modificado o la firma corresponde a otro archivo',
            'nombre_archivo': archivo.filename,
            'nombre_firma': firma_file.filename
        })
        
    except Exception as e:
        return jsonify({'error': f'Error al verificar firma: {str(e)}'}), 500

# WEBSOCKET EVENTS
@socketio.on('connect')
def handle_connect():
    """Cuando un cliente web se conecta"""
    session_id = request.sid
    # Inicialmente no sabemos el modo, se establecerá cuando el cliente envíe el evento 'establecer_modo'
    print(f"[WEB] Cliente conectado: {session_id}")

@socketio.on('establecer_modo')
def handle_establecer_modo(data):
    """Establece el modo (servidor o cliente) para esta sesión"""
    session_id = request.sid
    modo_servidor = data.get('modo_servidor', False)
    
    # Si ya está conectado, actualizar el modo
    if session_id in clientes_web:
        clientes_web[session_id]['modo_servidor'] = modo_servidor
    else:
        # Conectar al servidor de chat con el modo especificado
        if conectar_al_servidor_chat(session_id, modo_servidor=modo_servidor):
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
    
    # No permitir enviar mensajes en modo servidor
    cliente = clientes_web[session_id]
    if cliente.get('modo_servidor', False):
        emit('error', {'mensaje': 'El modo servidor es solo lectura'})
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
        cliente['file_writer'].write(json.dumps(paquete) + "\n")
        cliente['file_writer'].flush()
        
        # Confirmar al frontend con timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        emit('mensaje_enviado', {
            'mensaje': mensaje,
            'etiqueta': cliente['etiqueta'],
            'cliente_id': cliente['cid'],
            'timestamp': timestamp
        })
        
        # Emitir confirmación de envío exitoso
        emit('mensaje_confirmado', {
            'mensaje': mensaje,
            'timestamp': timestamp
        })
        
        # NOTA: No enviamos manualmente el mensaje al modo servidor aquí
        # porque el servidor de chat ya hace broadcast a todos los clientes
        # (incluyendo las sesiones en modo servidor), y lo recibirán a través
        # de recibir_mensajes_chat() para evitar duplicación
        
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

