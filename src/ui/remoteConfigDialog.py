"""
Diálogo para configurar la conexión remota a la base de datos.
"""

from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QMessageBox)
from PySide6.QtCore import Signal
from core.remote_db import RemoteDBManager

class RemoteConfigDialog(QDialog):
    connectionEstablished = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuración de conexión remota")
        self.setMinimumWidth(400)
        self.remote_manager = None  # Será establecido por MainWindow
        self._setup_ui()
        
    def setRemoteManager(self, manager):
        """Establece el gestor de conexión remota y conecta sus señales"""
        self.remote_manager = manager
        # Conectar señales del RemoteDBManager
        self.remote_manager.syncProgress.connect(self._show_status)
        self.remote_manager.syncError.connect(self._show_error)
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Host
        hostLayout = QHBoxLayout()
        hostLabel = QLabel("Host:")
        self.hostInput = QLineEdit()
        self.hostInput.setPlaceholderText("Ejemplo: 192.168.1.100")
        hostLayout.addWidget(hostLabel)
        hostLayout.addWidget(self.hostInput)
        layout.addLayout(hostLayout)
        
        # Puerto
        portLayout = QHBoxLayout()
        portLabel = QLabel("Puerto:")
        self.portInput = QLineEdit()
        self.portInput.setText("22")
        self.portInput.setPlaceholderText("Puerto SSH (por defecto: 22)")
        portLayout.addWidget(portLabel)
        portLayout.addWidget(self.portInput)
        layout.addLayout(portLayout)
        
        # Usuario
        userLayout = QHBoxLayout()
        userLabel = QLabel("Usuario:")
        self.userInput = QLineEdit()
        self.userInput.setPlaceholderText("Nombre de usuario SSH")
        userLayout.addWidget(userLabel)
        userLayout.addWidget(self.userInput)
        layout.addLayout(userLayout)
        
        # Contraseña
        passLayout = QHBoxLayout()
        passLabel = QLabel("Contraseña:")
        self.passInput = QLineEdit()
        self.passInput.setEchoMode(QLineEdit.PasswordEchoOnEdit)
        passLayout.addWidget(passLabel)
        passLayout.addWidget(self.passInput)
        layout.addLayout(passLayout)
        
        # Botones
        buttonLayout = QHBoxLayout()
        self.connectButton = QPushButton("Conectar")
        self.connectButton.clicked.connect(self._try_connect)
        self.closeButton = QPushButton("Cerrar")
        self.closeButton.clicked.connect(self.reject)
        
        buttonLayout.addWidget(self.connectButton)
        buttonLayout.addWidget(self.closeButton)
        layout.addLayout(buttonLayout)
        
    def _show_error(self, message):
        """Muestra un mensaje de error"""
        QMessageBox.critical(self, "Error", message)
        
    def _show_status(self, message):
        """Muestra un mensaje de estado"""
        QMessageBox.information(self, "Estado", message)
        
    def _try_connect(self):
        """Intenta establecer la conexión con el servidor remoto"""
        try:
            # Obtener datos de conexión
            host = self.hostInput.text().strip()
            port = int(self.portInput.text().strip())
            username = self.userInput.text().strip()
            password = self.passInput.text()
            
            if not all([host, username, password]):
                raise ValueError("Todos los campos son obligatorios")
                
            # Intentar conexión
            self.remote_manager.connect(
                hostname=host,
                username=username,
                password=password,
                port=port
            )
            
            self.connectionEstablished.emit()
            self.accept()
            
        except Exception as e:
            self._show_error(f"Error al conectar: {str(e)}")
            
    def closeEvent(self, event):
        """Maneja el cierre del diálogo"""
        if not self.result():
            self.remote_manager.disconnect()
        super().closeEvent(event)
        
        # Conectar señales del RemoteDBManager
        self.remote_manager.syncStarted.connect(lambda: self._set_buttons_enabled(False))
        self.remote_manager.syncCompleted.connect(lambda: self._set_buttons_enabled(True))
        self.remote_manager.syncError.connect(self._show_error)
        self.remote_manager.syncProgress.connect(lambda msg: self._show_status(msg))
        
    def _toggle_auth_method(self, state):
        """Alterna entre autenticación por contraseña o archivo de clave"""
        self.passLayout.setEnabled(not state)
        self.keyFileLayout.setEnabled(state)
        self.passInput.setEnabled(not state)
        self.keyFileInput.setEnabled(state)
        self.keyFileBrowse.setEnabled(state)
        
    def _browse_key_file(self):
        """Abre un diálogo para seleccionar el archivo de clave privada"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Seleccionar archivo de clave privada",
            "",
            "Todos los archivos (*.*)"
        )
        if file_path:
            self.keyFileInput.setText(file_path)
            
    def _set_buttons_enabled(self, enabled):
        """Habilita/deshabilita los botones durante operaciones"""
        self.testButton.setEnabled(enabled)
        self.syncFromRemoteButton.setEnabled(enabled)
        self.syncToRemoteButton.setEnabled(enabled)
        self.closeButton.setEnabled(enabled)
        
    def _show_error(self, message):
        """Muestra un mensaje de error"""
        QMessageBox.critical(self, "Error", message)
        
    def _show_status(self, message):
        """Muestra un mensaje de estado"""
        QMessageBox.information(self, "Estado", message)
        
    def _test_connection(self):
        """Prueba la conexión con el servidor remoto"""
        try:
            self._set_buttons_enabled(False)
            
            # Obtener datos de conexión
            host = self.hostInput.text().strip()
            port = int(self.portInput.text().strip())
            username = self.userInput.text().strip()
            
            if not all([host, username]):
                raise ValueError("Host y usuario son campos obligatorios")
            
            # Determinar método de autenticación
            if self.useKeyFile.isChecked():
                key_file = self.keyFileInput.text().strip()
                if not key_file:
                    raise ValueError("Debe seleccionar un archivo de clave privada")
                password = None
            else:
                password = self.passInput.text()
                if not password:
                    raise ValueError("La contraseña es obligatoria")
                key_file = None
            
            # Intentar conexión
            self.remote_manager.connect(
                hostname=host,
                username=username,
                password=password,
                key_filename=key_file,
                port=port
            )
            
            QMessageBox.information(self, "Éxito", "Conexión establecida correctamente")
            self.syncFromRemoteButton.setEnabled(True)
            self.syncToRemoteButton.setEnabled(True)
            
        except Exception as e:
            self._show_error(f"Error al conectar: {str(e)}")
        finally:
            self._set_buttons_enabled(True)
            
    def _sync_from_remote(self):
        """Sincroniza la base de datos desde el servidor remoto"""
        try:
            remote_path = self.remotePathInput.text().strip()
            if not remote_path:
                raise ValueError("Debe especificar la ruta remota de la base de datos")
                
            reply = QMessageBox.question(
                self,
                "Confirmar sincronización",
                "Esta operación sobrescribirá su base de datos local. ¿Desea continuar?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.remote_manager.sync_remote_to_local(remote_path)
                
        except Exception as e:
            self._show_error(f"Error al sincronizar: {str(e)}")
            
    def _sync_to_remote(self):
        """Sincroniza la base de datos hacia el servidor remoto"""
        try:
            remote_path = self.remotePathInput.text().strip()
            if not remote_path:
                raise ValueError("Debe especificar la ruta remota de la base de datos")
                
            reply = QMessageBox.question(
                self,
                "Confirmar sincronización",
                "Esta operación sobrescribirá la base de datos remota. ¿Desea continuar?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.remote_manager.sync_local_to_remote(remote_path)
                
        except Exception as e:
            self._show_error(f"Error al sincronizar: {str(e)}")
            
    def closeEvent(self, event):
        """Maneja el cierre del diálogo"""
        self.remote_manager.disconnect()
        super().closeEvent(event)
