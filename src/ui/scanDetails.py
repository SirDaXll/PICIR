from typing import Dict, Any
import os
import subprocess
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QTableWidget, QTableWidgetItem,
    QLabel, QWidget, QGridLayout, QHeaderView, QPushButton, QScrollArea,
    QMessageBox
)
from styles.themes import DARK_THEME, LIGHT_THEME

# Constants for UI
DISPLAY_ROLE = Qt.ItemDataRole.DisplayRole
USER_ROLE = Qt.ItemDataRole.UserRole
INTERACTIVE_MODE = QHeaderView.ResizeMode.Interactive
NO_EDIT_TRIGGERS = QTableWidget.EditTrigger.NoEditTriggers
ALIGN_CENTER = Qt.AlignmentFlag.AlignCenter
MESSAGE_YES = QMessageBox.StandardButton.Yes
MESSAGE_NO = QMessageBox.StandardButton.No
BLUE_COLOR = QColor('blue')


class ScanDetailsDialog(QDialog):
    def __init__(self, scan_details: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.scan_details = scan_details
        self.setWindowTitle("Detalles del escaneo")
        self.setMinimumSize(800, 600)
        self.setup_ui()

    def format_time(self, seconds: float) -> str:
        """Convierte segundos a formato hh:mm:ss:ms"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds_remainder = seconds % 60
        seconds_int = int(seconds_remainder)
        milliseconds = int((seconds_remainder - seconds_int) * 1000)
        
        return f"{hours:02d}:{minutes:02d}:{seconds_int:02d}.{milliseconds:03d}"

    def handle_vulnerability_click(self, item):
        # Verificar si el ítem es de la columna de descripción
        if item.column() == 4:  # columna de descripción
            text = item.text()
            # Buscar URLs en el texto (formato básico http:// o https://)
            if text.startswith(("http://", "https://")):
                url = text.split()[0]  # Tomar la primera palabra que sería la URL
                msg_box = QMessageBox(self)
                msg_box.setIcon(QMessageBox.Icon.Question)
                msg_box.setWindowTitle("Abrir URL")
                msg_box.setText(f"\n¿Desea abrir la siguiente URL en su navegador?\n\n"
                              f"{url:^50}\n\n"
                              f"En ella verá información sobre la vulnerabilidad.\n")
                msg_box.setStandardButtons(MESSAGE_YES | MESSAGE_NO)
                msg_box.setDefaultButton(MESSAGE_NO)
                msg_box.setMinimumWidth(400)
                response = msg_box.exec_()
                
                if response == MESSAGE_YES:
                    try:
                        # Obtener el usuario real (no root) que ejecutó sudo
                        real_user = os.environ.get('SUDO_USER')
                        
                        if real_user:
                            # Si estamos en sudo, ejecutar como el usuario original
                            cmd = ['sudo', '-u', real_user, 'xdg-open', url]
                        else:
                            # Si no estamos en sudo, ejecutar directamente
                            cmd = ['xdg-open', url]
                        
                        # Ejecutar el comando en segundo plano y redirigir la salida
                        subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=True
                        )
                    except Exception as e:
                        # Si falla, mostrar mensaje de error
                        error_box = QMessageBox(self)
                        error_box.setIcon(QMessageBox.Icon.Warning)
                        error_box.setWindowTitle("Error al abrir URL")
                        error_box.setText(f"\nNo se pudo abrir la URL automáticamente.\n\n"
                                        f"Por favor, copie y pegue la siguiente URL en su navegador:\n\n"
                                        f"{url:^50}\n")
                        error_box.setDetailedText(f"Detalles del error:\n{str(e)}")
                        error_box.setStandardButtons(QMessageBox.StandardButton.Ok)
                        error_box.setMinimumWidth(400)
                        error_box.exec_()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        
        # Crear tabs para diferentes secciones
        self.tab_widget = QTabWidget()
        
        # Tab de información general
        general_tab = QWidget()
        scroll_area = QScrollArea()
        scroll_area.setWidget(general_tab)
        scroll_area.setWidgetResizable(True)
        general_layout = QGridLayout(general_tab)
        
        general_info = self.scan_details["general"]
        labels = [
            ("🌐 IP del host:", general_info.get("ip_host", "No disponible")),
            ("📱 Dirección MAC:", general_info.get("mac_address", "No detectada")),
            ("💻 Sistema operativo:", general_info.get("sistema_operativo", "No detectado")),
            ("📅 Fecha y hora:", general_info.get("fecha", "No disponible")),
            ("🔍 Comando:", general_info.get("comando", "No disponible")),
            ("⏱️ Tiempo:", self.format_time(general_info.get("tiempo_respuesta", 0)))
        ]
        
        for i, (label, value) in enumerate(labels):
            general_layout.addWidget(QLabel(label), i, 0)
            value_label = QLabel(str(value))
            value_label.setWordWrap(True)
            general_layout.addWidget(value_label, i, 1)

        # Tab de puertos
        ports_tab = QWidget()
        ports_layout = QVBoxLayout(ports_tab)
        
        if not self.scan_details["puertos"]:
            # Si no hay puertos, mostrar mensaje
            no_ports_label = QLabel("No se encontraron puertos abiertos en este escaneo.")
            no_ports_label.setAlignment(ALIGN_CENTER)
            ports_layout.addWidget(no_ports_label)
        else:
            # Crear y configurar la tabla de puertos
            ports_table = QTableWidget()
            ports_table.setColumnCount(4)
            
            # Habilitar ordenamiento
            ports_table.setSortingEnabled(True)
            
            # Crear headers con íconos para la tabla de puertos
            protocol_header = QTableWidgetItem("Protocolo")
            protocol_header.setIcon(QIcon.fromTheme("emblem-system"))

            port_header = QTableWidgetItem("Puerto")
            port_header.setIcon(QIcon.fromTheme("network-wired"))
            
            service_header = QTableWidgetItem("Servicio")
            service_header.setIcon(QIcon.fromTheme("preferences-system-services"))
            
            version_header = QTableWidgetItem("Versión")
            version_header.setIcon(QIcon.fromTheme("package-x-generic"))
            
            # Establecer headers en la tabla de puertos
            ports_table.setHorizontalHeaderItem(0, protocol_header)
            ports_table.setHorizontalHeaderItem(1, port_header)
            ports_table.setHorizontalHeaderItem(2, service_header)
            ports_table.setHorizontalHeaderItem(3, version_header)
            
            # Configurar el ancho de las columnas
            header = ports_table.horizontalHeader()
            
            # Protocolo
            header.setSectionResizeMode(0, INTERACTIVE_MODE)
            ports_table.setColumnWidth(0, 100)
            
            # Puerto
            header.setSectionResizeMode(1, INTERACTIVE_MODE)
            ports_table.setColumnWidth(1, 100)
            
            # Servicio
            header.setSectionResizeMode(2, INTERACTIVE_MODE)
            ports_table.setColumnWidth(2, 150)
            
            # Versión
            header.setSectionResizeMode(3, INTERACTIVE_MODE)
            ports_table.setColumnWidth(3, 200)
            
            # Configuraciones adicionales
            header.setStretchLastSection(True)
            header.setSortIndicatorShown(True)
            ports_table.setEditTriggers(NO_EDIT_TRIGGERS)
            ports_table.verticalHeader().setDefaultSectionSize(30)
            ports_table.verticalHeader().setMinimumSectionSize(30)

            # Deshabilitar ordenamiento mientras se agregan items
            ports_table.setSortingEnabled(False)
            for port in self.scan_details["puertos"]:
                row = ports_table.rowCount()
                ports_table.insertRow(row)
                
                # Puerto (ordenable numéricamente)
                port_item = QTableWidgetItem()
                port_item.setData(DISPLAY_ROLE, str(port["puerto"]))
                port_item.setData(USER_ROLE, int(port["puerto"]))
                ports_table.setItem(row, 1, port_item)
                
                # Los demás campos ordenables como texto
                ports_table.setItem(row, 0, QTableWidgetItem(port["protocolo"].upper()))
                ports_table.setItem(row, 2, QTableWidgetItem(port["servicio"]))
                ports_table.setItem(row, 3, QTableWidgetItem(port["version"]))
            
            # Reactivar ordenamiento
            ports_table.setSortingEnabled(True)
            
            ports_layout.addWidget(ports_table)

        # Tab de vulnerabilidades
        vulns_tab = QWidget()
        vulns_layout = QVBoxLayout(vulns_tab)
        
        if not self.scan_details["vulnerabilidades"]:
            # Si no hay vulnerabilidades, mostrar mensaje
            no_vulns_label = QLabel("No se encontraron vulnerabilidades en este escaneo.")
            no_vulns_label.setAlignment(ALIGN_CENTER)
            vulns_layout.addWidget(no_vulns_label)
        else:
            # Crear y configurar la tabla de vulnerabilidades
            vulns_table = QTableWidget()
            vulns_table.setColumnCount(5)  # Aumentamos a 5 columnas
            
            # Habilitar ordenamiento
            vulns_table.setSortingEnabled(True)
            
            # Crear headers con íconos para la tabla de vulnerabilidades
            vuln_port_header = QTableWidgetItem("Puerto")
            vuln_port_header.setIcon(QIcon.fromTheme("network-wired"))
            
            vuln_protocol_header = QTableWidgetItem("Protocolo")
            vuln_protocol_header.setIcon(QIcon.fromTheme("emblem-system"))
            
            exploitable_header = QTableWidgetItem("Explotable")
            exploitable_header.setIcon(QIcon.fromTheme("security-low"))
            
            cvss_header = QTableWidgetItem("CVSS")
            cvss_header.setIcon(QIcon.fromTheme("security-medium"))
            
            description_header = QTableWidgetItem("Descripción")
            description_header.setIcon(QIcon.fromTheme("dialog-warning"))
            
            # Establecer headers en la tabla de vulnerabilidades
            vulns_table.setHorizontalHeaderItem(1, vuln_port_header)
            vulns_table.setHorizontalHeaderItem(0, vuln_protocol_header)
            vulns_table.setHorizontalHeaderItem(2, exploitable_header)
            vulns_table.setHorizontalHeaderItem(3, cvss_header)
            vulns_table.setHorizontalHeaderItem(4, description_header)
            
            # Configurar el ancho de las columnas
            header = vulns_table.horizontalHeader()
            
            # Puerto
            header.setSectionResizeMode(1, INTERACTIVE_MODE)
            vulns_table.setColumnWidth(0, 100)
            
            # Protocolo
            header.setSectionResizeMode(0, INTERACTIVE_MODE)
            vulns_table.setColumnWidth(1, 100)
            
            # Explotable
            header.setSectionResizeMode(2, INTERACTIVE_MODE)
            vulns_table.setColumnWidth(2, 100)
            
            # CVSS
            header.setSectionResizeMode(3, INTERACTIVE_MODE)
            vulns_table.setColumnWidth(3, 80)
            
            # Descripción (con URLs clicables)
            header.setSectionResizeMode(4, INTERACTIVE_MODE)
            vulns_table.setColumnWidth(4, 320)
            
            # Configuraciones adicionales
            header.setStretchLastSection(True)
            header.setSortIndicatorShown(True)
            vulns_table.setEditTriggers(NO_EDIT_TRIGGERS)
            vulns_table.verticalHeader().setDefaultSectionSize(30)
            vulns_table.verticalHeader().setMinimumSectionSize(30)
            
            # Conectar el evento de clic
            vulns_table.itemClicked.connect(self.handle_vulnerability_click)
            
            # Deshabilitar ordenamiento mientras se agregan items
            vulns_table.setSortingEnabled(False)
            for vuln in self.scan_details["vulnerabilidades"]:
                row = vulns_table.rowCount()
                vulns_table.insertRow(row)
                
                # Puerto (ordenable numéricamente)
                port_item = QTableWidgetItem()
                port_item.setData(DISPLAY_ROLE, str(vuln["puerto"]))
                port_item.setData(USER_ROLE, int(vuln["puerto"]))
                vulns_table.setItem(row, 1, port_item)
                
                # Protocolo
                vulns_table.setItem(row, 0, QTableWidgetItem(vuln["protocolo"].upper()))
                
                # Explotable (ordenable)
                exploitable_item = QTableWidgetItem()
                exploitable_item.setData(DISPLAY_ROLE, "Sí" if vuln["explotable"] else "No")
                exploitable_item.setData(USER_ROLE, 1 if vuln["explotable"] else 0)
                if vuln["explotable"]:
                    exploitable_item.setBackground(QColor(255, 200, 200))  # Rojo claro
                vulns_table.setItem(row, 2, exploitable_item)
                
                # CVSS (ordenable numéricamente)
                cvss_item = QTableWidgetItem()
                cvss_score = vuln.get("cvss", 0.0)  # Obtener CVSS, 0.0 si no existe
                cvss_item.setData(DISPLAY_ROLE, f"{cvss_score:.1f}")
                cvss_item.setData(USER_ROLE, float(cvss_score))
                # Colorear según la severidad del CVSS
                if cvss_score >= 9.0:
                    cvss_item.setBackground(QColor(255, 100, 100))  # Rojo más intenso
                elif cvss_score >= 7.0:
                    cvss_item.setBackground(QColor(255, 150, 150))  # Rojo medio
                elif cvss_score >= 4.0:
                    cvss_item.setBackground(QColor(255, 200, 150))  # Naranja claro
                elif cvss_score > 0:
                    cvss_item.setBackground(QColor(255, 255, 150))  # Amarillo claro
                vulns_table.setItem(row, 3, cvss_item)
                
                # Crear ítem de descripción con URL clicable
                desc_item = QTableWidgetItem(vuln["descripcion"])
                if vuln["descripcion"].startswith(("http://", "https://")):
                    desc_item.setForeground(BLUE_COLOR)
                    desc_item.setToolTip("Haz clic para abrir en el navegador")
                vulns_table.setItem(row, 4, desc_item)
            
            # Reactivar ordenamiento
            vulns_table.setSortingEnabled(True)
            
            vulns_layout.addWidget(vulns_table)
        
        # Agregar tabs al widget principal
        self.tab_widget.addTab(scroll_area, "ℹ️ Información general")
        self.tab_widget.addTab(ports_tab, "🔌 Puertos")
        self.tab_widget.addTab(vulns_tab, "⚠️ Vulnerabilidades")
        
        main_layout.addWidget(self.tab_widget)
        
        # Botón de cerrar
        close_button = QPushButton("Cerrar")
        close_button.clicked.connect(self.accept)
        main_layout.addWidget(close_button)

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
        
        # Estilos para las tablas
        table_style = f"""
            QTableWidget {{
                background-color: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                gridline-color: {border_color};
                border-radius: 4px;
            }}
            QTableWidget::item {{
                padding: 4px;
            }}
            QTableWidget::item:hover {{
                background-color: {selection_color};
            }}
            QTableWidget::item:selected {{
                background-color: {'#505050' if is_dark else '#d0d0d0'};
            }}
            QHeaderView::section {{
                background-color: {bg_color};
                color: {text_color};
                padding: 4px;
                border: 1px solid {border_color};
            }}
        """
        
        # Estilos para pestañas
        tab_style = f"""
            QTabWidget::pane {{
                border: 1px solid {border_color};
                background-color: {bg_color};
                top: -1px;
            }}
            QTabBar::tab {{
                background-color: {bg_color};
                color: {text_color};
                padding: 8px 12px;
                border: 1px solid {border_color};
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {selection_color};
            }}
            QTabBar::tab:hover {{
                background-color: {'#404040' if is_dark else '#e0e0e0'};
            }}
        """
        
        # Estilos para el scroll area
        scroll_style = f"""
            QScrollArea {{
                background-color: {bg_color};
                border: none;
            }}
            QScrollBar:vertical {{
                background-color: {bg_color};
                width: 12px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {'#505050' if is_dark else '#c0c0c0'};
                min-height: 20px;
                border-radius: 6px;
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
        """
        
        # Aplicar el tema base
        self.setStyleSheet(DARK_THEME if is_dark else LIGHT_THEME)
        
        # Aplicar estilos específicos
        self.tab_widget.setStyleSheet(tab_style)
        
        # Aplicar a todas las tablas
        for table in self.findChildren(QTableWidget):
            table.setStyleSheet(table_style)
            
            # Si es la tabla de vulnerabilidades (tiene 5 columnas)
            if table.columnCount() == 5:
                # Primero aplicar el color de texto por defecto a todas las celdas
                for row in range(table.rowCount()):
                    for col in range(table.columnCount()):
                        item = table.item(row, col)
                        if item:
                            item.setForeground(QColor(text_color))
                
                # Luego aplicar el color azul solo a las URLs
                for row in range(table.rowCount()):
                    desc_item = table.item(row, 4)  # Columna de descripción
                    if desc_item and desc_item.text().startswith(("http://", "https://")):
                        # Usar un azul más brillante para modo oscuro y uno más oscuro para modo claro
                        url_color = QColor(100, 181, 246) if is_dark else QColor(25, 118, 210)
                        desc_item.setForeground(url_color)
        
        # Aplicar a todas las áreas de desplazamiento
        for scroll in self.findChildren(QScrollArea):
            scroll.setStyleSheet(scroll_style)
            
        # Aplicar a todas las etiquetas
        for label in self.findChildren(QLabel):
            label.setStyleSheet(f"color: {text_color}; background-color: transparent;")
            
        # Forzar actualización visual
        self.update()


