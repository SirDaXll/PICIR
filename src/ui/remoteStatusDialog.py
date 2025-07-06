"""
Diálogo para mostrar el estado de la conexión remota.
"""

from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout

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
        statusLabel = QLabel("✅ Conectado al servidor remoto")
        statusLabel.setStyleSheet("color: green; font-weight: bold;")
        layout.addWidget(statusLabel)
        
        # Botones
        buttonLayout = QHBoxLayout()
        self.disconnectButton = QPushButton("Desconectar")
        self.disconnectButton.clicked.connect(self._disconnect)
        self.closeButton = QPushButton("Cerrar")
        self.closeButton.clicked.connect(self.accept)
        
        buttonLayout.addWidget(self.disconnectButton)
        buttonLayout.addWidget(self.closeButton)
        layout.addLayout(buttonLayout)
        
    def _disconnect(self):
        """Desconecta del servidor remoto y cierra el diálogo"""
        self.remote_manager.disconnect()
        self.accept()
