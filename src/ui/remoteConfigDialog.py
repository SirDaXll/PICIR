"""
Diálogo para configurar la conexión remota a la base de datos.
"""

from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QLineEdit, QPushButton, QMessageBox, QWidget)
from PySide6.QtCore import Signal, QRegularExpression
from PySide6.QtGui import QRegularExpressionValidator, QIcon
import paramiko
import os
from styles.themes import DARK_THEME, LIGHT_THEME

class RemoteConfigDialog(QDialog):
    connection_established = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configuración de conexión remota")
        self.setMinimumWidth(400)
        self.remote_manager = None  # Será establecido por MainWindow

        # Establecer el ícono de la aplicación
        icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources", "icons", "app.svg")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self._setup_ui()
        
        # Aplicar el tema actual del padre si existe
        if parent and hasattr(parent, 'current_theme'):
            self.apply_theme(parent.current_theme)
    
    def apply_theme(self, theme):
        """Aplica el tema especificado al diálogo y todos sus widgets"""
        style = DARK_THEME if theme == "dark" else LIGHT_THEME
        
        # Aplicar tema al diálogo principal
        self.setStyleSheet(style)
        
        # Aplicar tema a cada tipo específico de widget
        for line_edit in self.findChildren(QLineEdit):
            line_edit.setStyleSheet(style)
        
        for button in self.findChildren(QPushButton):
            button.setStyleSheet(style)
            
        for label in self.findChildren(QLabel):
            label.setStyleSheet(style)
            
        # Aplicar a cualquier otro widget que pueda existir
        for widget in self.findChildren(QWidget):
            if not isinstance(widget, (QLineEdit, QPushButton, QLabel)):
                widget.setStyleSheet(style)
        
    def set_remote_manager(self, manager):
        """Establece el gestor de conexión remota"""
        # Desconectar todas las señales del gestor anterior si existe
        if self.remote_manager:
            try:
                self.remote_manager.sync_progress.disconnect()
                self.remote_manager.sync_error.disconnect()
            except (TypeError, RuntimeError):
                # Las señales podrían no estar conectadas
                pass
        
        self.remote_manager = manager
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Host (IP)
        host_layout = QHBoxLayout()
        host_label = QLabel("Host:")
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Ejemplo: 192.168.1.100")
        
        # Validador para dirección IP
        ip_regex = QRegularExpression(
            r"^(?:[0-9]{1,3}\.){0,3}[0-9]{1,3}$"  # Permite entrada parcial de IP
        )
        ip_validator = QRegularExpressionValidator(ip_regex)
        self.host_input.setValidator(ip_validator)
        
        host_layout.addWidget(host_label)
        host_layout.addWidget(self.host_input)
        layout.addLayout(host_layout)
        
        # Puerto
        port_layout = QHBoxLayout()
        port_label = QLabel("Puerto:")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Puerto TCP de SSH (Por defecto: 22)")
        
        # Validador para puerto (1-65535)
        port_regex = QRegularExpression(r"^[1-9]\d{0,4}$")
        port_validator = QRegularExpressionValidator(port_regex)
        self.port_input.setValidator(port_validator)
        
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        layout.addLayout(port_layout)
        
        # Usuario
        user_layout = QHBoxLayout()
        user_label = QLabel("Usuario:")
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Nombre de usuario SSH")
        user_layout.addWidget(user_label)
        user_layout.addWidget(self.user_input)
        layout.addLayout(user_layout)
        
        # Contraseña
        self.pass_layout = QHBoxLayout()
        pass_label = QLabel("Contraseña:")
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_layout.addWidget(pass_label)
        self.pass_layout.addWidget(self.pass_input)
        layout.addLayout(self.pass_layout)
        
        # Botones
        button_layout = QHBoxLayout()
        self.connect_button = QPushButton("Conectar")
        self.connect_button.clicked.connect(self._try_connect)
        self.close_button = QPushButton("Cerrar")
        self.close_button.clicked.connect(self.reject)

        button_layout.addWidget(self.connect_button)
        button_layout.addWidget(self.close_button)
        layout.addLayout(button_layout)
        
    def _show_message(self, title, text, icon):
        """Muestra un mensaje."""
        # Hacemos el mensaje corto más ancho añadiendo espacios a los lados
        padded_text = text.center(50)  # Centrar en 50 caracteres con espacios
        
        msg_box = QMessageBox(self)
        msg_box.setIcon(icon)
        msg_box.setWindowTitle(title)
        msg_box.setText(f"{padded_text}\n")
        msg_box.setMinimumWidth(400)
        msg_box.exec()

    def _show_error(self, title, text):
        """Muestra un mensaje de error."""
        self._show_message(title, text, QMessageBox.Icon.Critical)

    def _show_info(self, title, text):
        """Muestra un mensaje informativo."""
        self._show_message(title, text, QMessageBox.Icon.Information)
        
    def _try_connect(self):
        """Intenta establecer la conexión con el servidor remoto"""
        try:
            # Obtener datos de conexión
            host = self.host_input.text().strip()
            port_text = self.port_input.text().strip()
            username = self.user_input.text().strip()
            password = self.pass_input.text()
            
            # Validar que todos los campos estén completos
            if not all([host, port_text, username, password]):
                raise ValueError("Todos los campos son obligatorios")
                
            # Validar formato de IP
            ip_parts = host.split('.')
            if len(ip_parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in ip_parts):
                raise ValueError("La dirección IP debe tener el formato correcto (ejemplo: 192.168.1.100)")
            
            # Validar puerto
            try:
                port = int(port_text)
                if not 1 <= port <= 65535:
                    raise ValueError("El puerto debe estar entre 1 y 65535")
            except ValueError:
                raise ValueError("El puerto debe ser un número válido")
                
            # Intentar conexión
            if self.remote_manager is None:
                raise RuntimeError("El gestor de conexión remota no está configurado")
            try:
                self.remote_manager.connect_to_server(
                    hostname=host,
                    username=username,
                    password=password,
                    port=port
                )
                
                # Mostrar mensaje de éxito
                self._show_info("Conexión exitosa", f"Conexión establecida exitosamente con {username}@{host}")
                self.connection_established.emit()
                self.accept()
                
            except paramiko.AuthenticationException:
                self._show_error("Error de autenticación", "Usuario o contraseña incorrectos")
            except paramiko.SSHException as e:
                self._show_error("Error de SSH", str(e))
            except Exception as e:
                self._show_error("Error al conectar", str(e))
            
        except ValueError as e:
            self._show_error("Error de validación", str(e))
            
    def closeEvent(self, event):  # noqa: N802
        """Maneja el cierre del diálogo"""
        if self.remote_manager is not None:
            self.remote_manager.close_connections()
        super().closeEvent(event)


