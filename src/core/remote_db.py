"""
Módulo para manejar la conexión remota y sincronización de la base de datos SQLite.
"""

import os
import paramiko
from datetime import datetime
from PySide6.QtCore import QObject, Signal
from core.constants import DB_NAME

class RemoteDBManager(QObject):
    """Clase para manejar la conexión y sincronización con la base de datos remota."""
    
    # Señales para notificar eventos
    sync_started = Signal()
    sync_completed = Signal()
    sync_error = Signal(str)
    sync_progress = Signal(str)

    def __init__(self):
        super().__init__()
        self.sftp = None
        self.ssh = None
        self._temp_db = None
    
    def connect_to_server(self, hostname, username, password=None, key_filename=None, port=22):
        """
        Establece la conexión SSH/SFTP con el servidor remoto.
        
        Args:
            hostname (str): Nombre o IP del servidor remoto
            username (str): Nombre de usuario para la conexión
            password (str, optional): Contraseña para la conexión
            key_filename (str, optional): Ruta al archivo de clave privada SSH
            port (int): Puerto SSH (por defecto 22)
            
        Raises:
            Exception: Si hay un error en la conexión
        """
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Intentar conexión
            self.ssh.connect(
                hostname=hostname,
                username=username,
                password=password,
                key_filename=key_filename,
                port=port
            )
            
            # Abrir sesión SFTP
            self.sftp = self.ssh.open_sftp()
            self.sync_progress.emit("Conexión establecida exitosamente")
            
        except Exception as e:
            self.sync_error.emit(f"Error al conectar: {str(e)}")
            raise
    
    def close_connections(self):
        """Cierra las conexiones SSH y SFTP."""
        if self.sftp:
            self.sftp.close()
        if self.ssh:
            self.ssh.close()
        self.sftp = None
        self.ssh = None
    
    def sync_remote_to_local(self, remote_path):
        """
        Sincroniza la base de datos remota con la local.
        
        Args:
            remote_path (str): Ruta completa al archivo de base de datos en el servidor remoto
        """
        if not self.sftp:
            self.sync_error.emit("No hay conexión SFTP establecida")
            return False
            
        try:
            self.sync_started.emit()
            self.sync_progress.emit("Iniciando sincronización desde remoto...")
            
            # Crear directorio local si no existe
            os.makedirs(os.path.dirname(DB_NAME), exist_ok=True)
            
            # Crear backup de la base de datos local si existe
            if os.path.exists(DB_NAME):
                backup_name = f"{DB_NAME}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                os.rename(DB_NAME, backup_name)
                self.sync_progress.emit(f"Backup creado: {backup_name}")
            
            # Descargar base de datos remota
            self.sftp.get(remote_path, DB_NAME)
            self.sync_progress.emit("Base de datos sincronizada exitosamente")
            self.sync_completed.emit()
            return True
            
        except Exception as e:
            self.sync_error.emit(f"Error durante la sincronización: {str(e)}")
            return False
    
    def sync_local_to_remote(self, remote_path):
        """
        Sincroniza la base de datos local con la remota.
        
        Args:
            remote_path (str): Ruta completa al archivo de base de datos en el servidor remoto
        """
        if not self.sftp:
            self.sync_error.emit("No hay conexión SFTP establecida")
            return False
            
        try:
            self.sync_started.emit()
            self.sync_progress.emit("Iniciando sincronización hacia remoto...")
            
            # Verificar que existe la base de datos local
            if not os.path.exists(DB_NAME):
                self.sync_error.emit("No existe base de datos local para sincronizar")
                return False
            
            # Crear backup remoto si existe el archivo
            try:
                self.sftp.stat(remote_path)  # Verificar si existe el archivo
                backup_name = f"{remote_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                self.sftp.rename(remote_path, backup_name)
                self.sync_progress.emit(f"Backup remoto creado: {backup_name}")
            except FileNotFoundError:
                # Si no existe el archivo remoto, continuamos
                pass
            except Exception as e:
                self.sync_error.emit(f"Error al crear backup remoto: {str(e)}")
                # Continuamos de todas formas
            
            # Subir base de datos local
            self.sftp.put(DB_NAME, remote_path)
            self.sync_progress.emit("Base de datos sincronizada exitosamente")
            self.sync_completed.emit()
            return True
            
        except Exception as e:
            self.sync_error.emit(f"Error durante la sincronización: {str(e)}")
            return False
    
    def is_connected(self):
        """Verifica si hay una conexión activa al servidor remoto.
        
        Returns:
            bool: True si hay una conexión activa, False en caso contrario
        """
        if self.ssh is not None:
            transport = self.ssh.get_transport()
            return transport is not None and transport.is_active()
        return False
    
    def __del__(self):
        """Asegurar que se cierren las conexiones al destruir el objeto."""
        self.close_connections()
