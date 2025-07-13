"""
Diálogo para seleccionar base de datos desde una conexión SFTP.
"""

from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QTreeWidget, QTreeWidgetItem)
from PySide6.QtCore import Signal
from styles.themes import DARK_THEME, LIGHT_THEME
import os

class RemoteFileSelector(QDialog):
    file_selected = Signal(str)  # Emite la ruta del archivo seleccionado

    def __init__(self, remote_manager, parent=None):
        super().__init__(parent)
        self.remote_manager = remote_manager
        self.sftp = None
        self.current_path = "/"
        self.setWindowTitle("Seleccionar base de datos remoto")
        self.setMinimumSize(500, 400)
        self._setup_ui()
        
        # Obtener el tema actual del padre si existe
        if parent and hasattr(parent, 'current_theme'):
            self.apply_theme(parent.current_theme)
        else:
            self.apply_theme('light')  # tema por defecto
            
        self._init_sftp()
        self._populate_tree()

    def apply_theme(self, theme):
        """Aplica el tema especificado al diálogo y sus widgets.
        
        Args:
            theme (str): 'light' o 'dark'
        """
        is_dark = theme == 'dark'
        bg_color = "#2b2b2b" if is_dark else "#f0f0f0"
        text_color = "#ffffff" if is_dark else "#000000"
        selection_color = "#404040" if is_dark else "#e0e0e0"
        border_color = "#404040" if is_dark else "#c0c0c0"
        
        # Estilo para QTreeWidget
        tree_style = f"""
            QTreeWidget {{
                background-color: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 4px;
            }}
            QTreeWidget::item {{
                padding: 4px;
            }}
            QTreeWidget::item:hover {{
                background-color: {selection_color};
            }}
            QTreeWidget::item:selected {{
                background-color: {'#505050' if is_dark else '#d0d0d0'};
            }}
            QHeaderView::section {{
                background-color: {bg_color};
                color: {text_color};
                padding: 4px;
                border: 1px solid {border_color};
            }}
        """
        
        # Aplicar el tema base
        self.setStyleSheet(DARK_THEME if is_dark else LIGHT_THEME)
        
        # Aplicar estilos específicos
        self.tree.setStyleSheet(tree_style)
        
        # Asegurar que los botones y labels tienen el estilo correcto
        button_style = f"""
            QPushButton {{
                background-color: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 4px;
                padding: 6px 12px;
                min-width: 80px;
            }}
            QPushButton:hover {{
                background-color: {selection_color};
            }}
            QPushButton:pressed {{
                background-color: {'#303030' if is_dark else '#d0d0d0'};
            }}
        """
        
        self.select_button.setStyleSheet(button_style)
        self.cancel_button.setStyleSheet(button_style)
        self.path_label.setStyleSheet(f"color: {text_color};")

    def _init_sftp(self):
        """Inicializa la conexión SFTP"""
        if not self.remote_manager.ssh:
            raise Exception("No hay conexión SSH activa")
        self.sftp = self.remote_manager.ssh.open_sftp()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Ruta actual
        self.path_label = QLabel("/")
        layout.addWidget(self.path_label)
        
        # Árbol de archivos
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Nombre", "Tipo"])
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.tree)
        
        # Botones
        button_layout = QHBoxLayout()
        
        self.select_button = QPushButton("Seleccionar")
        self.select_button.clicked.connect(self._on_select)
        self.select_button.setEnabled(False)
        
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.select_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

    def _populate_tree(self, path="/"):
        """Rellena el árbol con los archivos y carpetas del path especificado"""
        self.tree.clear()
        self.current_path = path
        self.path_label.setText(path)
        
        try:
            # Verificar que tenemos una conexión SFTP activa
            if not self.sftp:
                self._init_sftp()
                
            if not self.sftp:
                raise Exception("No se pudo establecer la conexión SFTP")
            
            # Añadir el item para subir un nivel
            if path != "/":
                up_item = QTreeWidgetItem(["...", "Carpeta"])
                up_item.setData(0, 256, "..")  # Guardar un identificador especial
                self.tree.addTopLevelItem(up_item)
            
            # Listar contenido del directorio
            entries = []
            try:
                # Primero intentar listar el directorio actual
                entries = self.sftp.listdir_attr() if path == "/" else self.sftp.listdir_attr(path)
            except Exception as e:
                # Si falla, intentar listar el directorio home del usuario
                self.current_path = "."
                path = "."
                try:
                    entries = self.sftp.listdir_attr(".")
                except Exception as e:
                    raise Exception(f"No se pudo listar el directorio: {str(e)}")
            
            for entry in entries:
                name = entry.filename
                # Usar el modo de archivo para verificar si es directorio
                is_dir = bool(entry.st_mode & 0o40000)  # Verificar si es directorio usando el modo
                
                # Extensiones permitidas para bases de datos SQLite
                is_sqlite = name.lower().endswith(('.db', '.sqlite', '.db3', '.sqlite3'))
                if is_dir or is_sqlite:  # Mostrar carpetas y archivos SQLite
                    item = QTreeWidgetItem([
                        name,
                        "Carpeta" if is_dir else "Base de datos SQLite"
                    ])
                    
                    # Guardar el tipo y ruta completa como datos del item
                    full_path = name if path == "/" else os.path.join(path, name)
                    item.setData(0, 256, full_path)
                    item.setData(0, 257, "dir" if is_dir else "file")
                    
                    self.tree.addTopLevelItem(item)
        
        except Exception as e:
            self.tree.clear()
            error_item = QTreeWidgetItem([f"Error al listar directorio: {str(e)}", ""])
            self.tree.addTopLevelItem(error_item)

    def _on_item_double_clicked(self, item, column):
        """Maneja el doble clic en un item del árbol"""
        path = item.data(0, 256)
        item_type = item.data(0, 257)
        
        if path == "..":
            # Subir un nivel
            new_path = os.path.dirname(self.current_path)
            self._populate_tree(new_path if new_path else "/")
        elif item_type == "dir":
            # Entrar en la carpeta
            self._populate_tree(path)
        else:
            # Seleccionar el archivo
            self.select_button.setEnabled(True)
            self.selected_file = path

    def _on_select(self):
        """Maneja el clic en el botón Seleccionar"""
        current_item = self.tree.currentItem()
        if current_item:
            path = current_item.data(0, 256)
            item_type = current_item.data(0, 257)
            
            if item_type == "file":
                self.file_selected.emit(path)
                self.accept()

    def cleanup(self):
        """Limpia los recursos SFTP"""
        if self.sftp:
            try:
                self.sftp.close()
            except Exception:
                pass  # Ignorar errores al cerrar
            self.sftp = None

    def close_event(self, event):
        """Se llama cuando se cierra el diálogo"""
        self.cleanup()
        super().closeEvent(event)

    def reject(self):
        """Se llama cuando se cancela el diálogo"""
        self.cleanup()
        super().reject()

    def accept(self):
        """Se llama cuando se acepta el diálogo"""
        self.cleanup()
        super().accept()
