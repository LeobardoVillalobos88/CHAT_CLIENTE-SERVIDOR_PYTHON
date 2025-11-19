import socket
import ssl
import hmac
import hashlib
import json
import os
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from dotenv import load_dotenv

# CARGA DE VARIABLES DE ENTORNO
load_dotenv()
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "ClavePorDefecto").encode("utf-8")

# CONFIGURACIÓN SSL/TLS
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

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

# CLASE PRINCIPAL DEL CLIENTE GUI
class ClienteChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Seguro - Cliente")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Variables
        self.conn = None
        self.file_writer = None
        self.file_reader = None
        self.cid = -1
        self.etiqueta = "Cliente"
        self.conectado = False
        self.hilo_receptor = None
        
        # Crear interfaz
        self.crear_interfaz()
        
        # Intentar conectar automáticamente
        self.conectar()
    
    def crear_interfaz(self):
        # Frame principal
        main_frame = tk.Frame(self.root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Área de estado
        estado_frame = tk.Frame(main_frame)
        estado_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.label_estado = tk.Label(
            estado_frame, 
            text="Desconectado", 
            fg="red",
            font=("Arial", 10, "bold")
        )
        self.label_estado.pack(side=tk.LEFT)
        
        self.label_id = tk.Label(
            estado_frame,
            text="",
            font=("Arial", 9)
        )
        self.label_id.pack(side=tk.LEFT, padx=(10, 0))
        
        # Área de mensajes
        info_label = tk.Label(
            main_frame,
            text="Chat - Mensajes:",
            font=("Arial", 9, "bold")
        )
        info_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.text_area = scrolledtext.ScrolledText(
            main_frame,
            height=20,
            width=70,
            state=tk.DISABLED,
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.text_area.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Frame de entrada
        entrada_frame = tk.Frame(main_frame)
        entrada_frame.pack(fill=tk.X)
        
        self.entry_mensaje = tk.Entry(
            entrada_frame,
            font=("Arial", 11)
        )
        self.entry_mensaje.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry_mensaje.bind("<Return>", lambda e: self.enviar_mensaje())
        
        self.btn_enviar = tk.Button(
            entrada_frame,
            text="Enviar",
            command=self.enviar_mensaje,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=20
        )
        self.btn_enviar.pack(side=tk.RIGHT)
        
        # Botón conectar/desconectar
        self.btn_conectar = tk.Button(
            main_frame,
            text="Desconectar",
            command=self.desconectar,
            bg="#f44336",
            fg="white",
            font=("Arial", 9)
        )
        self.btn_conectar.pack(pady=(5, 0))
    
    def agregar_mensaje(self, mensaje, tipo="info"):
        """Agrega un mensaje al área de texto"""
        self.text_area.config(state=tk.NORMAL)
        
        if tipo == "enviado":
            self.text_area.insert(tk.END, f"[ENVIADO] {mensaje}\n", "enviado")
        elif tipo == "error":
            self.text_area.insert(tk.END, f"[ERROR] {mensaje}\n", "error")
        elif tipo == "sistema":
            self.text_area.insert(tk.END, f"[SISTEMA] {mensaje}\n", "sistema")
        else:
            self.text_area.insert(tk.END, f"{mensaje}\n")
        
        self.text_area.config(state=tk.DISABLED)
        self.text_area.see(tk.END)
        
        # Configurar colores
        self.text_area.tag_config("enviado", foreground="blue")
        self.text_area.tag_config("recibido", foreground="purple")
        self.text_area.tag_config("error", foreground="red")
        self.text_area.tag_config("sistema", foreground="green")
    
    def conectar(self):
        """Conecta al servidor"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn = context.wrap_socket(sock, server_hostname=HOST)
            self.conn.connect((HOST, PORT))
            
            self.cid = recibir_id(self.conn)
            self.etiqueta = f"Cliente {self.cid}" if self.cid > 0 else "Cliente"
            
            self.file_writer = self.conn.makefile('w', encoding='utf-8', newline='\n')
            self.file_reader = self.conn.makefile('r', encoding='utf-8', newline='\n')
            self.conectado = True
            
            # Iniciar hilo para recibir mensajes
            self.hilo_receptor = threading.Thread(target=self.recibir_mensajes, daemon=True)
            self.hilo_receptor.start()
            
            # Actualizar interfaz
            self.label_estado.config(text="Conectado (SSL/TLS)", fg="green")
            self.label_id.config(text=f"ID: {self.cid}")
            self.btn_conectar.config(text="Desconectar", bg="#f44336")
            self.entry_mensaje.config(state=tk.NORMAL)
            self.btn_enviar.config(state=tk.NORMAL)
            
            self.agregar_mensaje("Conexión segura establecida (SSL/TLS activo)", "sistema")
            self.agregar_mensaje(f"Conectado como: {self.etiqueta}", "sistema")
            
        except Exception as e:
            self.conectado = False
            self.label_estado.config(text="Error de conexión", fg="red")
            messagebox.showerror("Error", f"No se pudo conectar al servidor:\n{str(e)}")
            self.agregar_mensaje(f"Error de conexión: {str(e)}", "error")
    
    def recibir_mensajes(self):
        """Hilo para recibir mensajes del servidor"""
        try:
            for linea in self.file_reader:
                if not self.conectado:
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
                        
                        if cliente_id != self.cid:  # No mostrar nuestros propios mensajes (ya los mostramos al enviar)
                            etiqueta_remitente = f"Cliente {cliente_id}"
                            hora = f"[{timestamp}]" if timestamp else ""
                            self.root.after(0, self.agregar_mensaje, 
                                           f"{hora} {etiqueta_remitente}: {mensaje}", "recibido")
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            if self.conectado:
                self.root.after(0, self.agregar_mensaje, f"Error al recibir: {str(e)}", "error")
                self.root.after(0, self.desconectar)
    
    def desconectar(self):
        """Desconecta del servidor"""
        self.conectado = False
        try:
            if self.file_reader:
                self.file_reader.close()
            if self.file_writer:
                self.file_writer.close()
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        
        # Actualizar interfaz
        self.label_estado.config(text="Desconectado", fg="red")
        self.label_id.config(text="")
        self.btn_conectar.config(text="Conectar", bg="#4CAF50", command=self.conectar)
        self.entry_mensaje.config(state=tk.DISABLED)
        self.btn_enviar.config(state=tk.DISABLED)
        
        self.agregar_mensaje("Conexión cerrada", "sistema")
    
    def enviar_mensaje(self):
        """Envía un mensaje al servidor"""
        if not self.conectado:
            messagebox.showwarning("Advertencia", "No estás conectado al servidor")
            return
        
        mensaje = self.entry_mensaje.get().strip()
        if not mensaje:
            return
        
        try:
            paquete = {
                "msg": mensaje,
                "sha": sha256_hex(mensaje),
                "hmac": firmar(mensaje)
            }
            
            self.file_writer.write(json.dumps(paquete) + "\n")
            self.file_writer.flush()
            
            self.agregar_mensaje(f"{self.etiqueta}: {mensaje}", "enviado")
            self.entry_mensaje.delete(0, tk.END)
            
        except Exception as e:
            self.agregar_mensaje(f"Error al enviar: {str(e)}", "error")
            messagebox.showerror("Error", f"Error al enviar mensaje:\n{str(e)}")
            self.desconectar()
    
    def cerrar(self):
        """Cierra la aplicación"""
        if self.conectado:
            self.desconectar()
        self.root.destroy()

# PROGRAMA PRINCIPAL
def main():
    root = tk.Tk()
    app = ClienteChatGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.cerrar)
    root.mainloop()

if __name__ == "__main__":
    main()

