"""
Diálogo para mostrar el estado de la conexión remota.
"""

from PySide6.QtWidgets import (QDialog, QVBoxLayout, QLabel, QPushButton, 
                             QHBoxLayout, QMessageBox)

class RemoteStatusDialog(QDialog):
    def __init__(self, remote_manager, parent=None):
        super().__init__(parent)
        self.remote_manager = remote_manager
        self.setWindowTitle("Estado de conexión remota")
        self.setMinimumWidth(300)
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Mensaje de estado
        status_label = QLabel("✅ Conectado al servidor remoto")
        status_label.setStyleSheet("color: green; font-weight: bold;")
        layout.addWidget(status_label)
        
        # Botones
        button_layout = QHBoxLayout()
        self.disconnect_button = QPushButton("Desconectar")
        self.disconnect_button.clicked.connect(self._disconnect)
        self.close_button = QPushButton("Cerrar")
        self.close_button.clicked.connect(self.accept)
        
        button_layout.addWidget(self.disconnect_button)
        button_layout.addWidget(self.close_button)
        layout.addLayout(button_layout)
        
    def _disconnect(self):
        """Desconecta del servidor remoto y cierra el diálogo"""
        if self._show_question("Confirmar desconexión", "¿Está seguro de que desea desconectarse del servidor remoto?"):
            try:
                self.remote_manager.close_connections()
                self._show_info("Éxito", "Desconectado exitosamente del servidor remoto")
                self.accept()
            except Exception as e:
                self._show_error("Error", f"Error al desconectar: {str(e)}")

    def _show_message(self, title, text, icon, buttons=QMessageBox.StandardButton.Ok, default_button=QMessageBox.StandardButton.Ok):
        """Muestra un mensaje."""
        # Hacemos el mensaje corto más ancho añadiendo espacios a los lados
        padded_text = text.center(50)  # Centrar en 50 caracteres con espacios
        
        msg_box = QMessageBox(self)
        msg_box.setIcon(icon)
        msg_box.setWindowTitle(title)
        msg_box.setText(f"\n\n{padded_text}\n\n")
        msg_box.setStandardButtons(buttons)
        msg_box.setDefaultButton(default_button)
        msg_box.setMinimumWidth(400)
        return msg_box.exec()

    def _show_error(self, title, text):
        """Muestra un mensaje de error."""
        return self._show_message(title, text, QMessageBox.Icon.Critical)

    def _show_info(self, title, text):
        """Muestra un mensaje informativo."""
        return self._show_message(title, text, QMessageBox.Icon.Information)

    def _show_question(self, title, text):
        """Muestra un mensaje de confirmación."""
        return self._show_message(
            title,
            text,
            QMessageBox.Icon.Question,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
