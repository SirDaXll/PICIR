from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QTableWidget, QTableWidgetItem,
    QLabel, QWidget, QGridLayout, QHeaderView, QPushButton, QScrollArea,
    QMessageBox
)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QIcon
from typing import Dict, Any

class ScanDetailsDialog(QDialog):
    def __init__(self, scanDetails: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.scanDetails = scanDetails
        self.setWindowTitle("Detalles del escaneo")
        self.setMinimumSize(800, 600)
        self.setup_ui()

    def formatTime(self, seconds: float) -> str:
        """Convierte segundos a formato hh:mm:ss:ms"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secondsRemainder = seconds % 60
        secondsInt = int(secondsRemainder)
        milliseconds = int((secondsRemainder - secondsInt) * 1000)
        
        return f"{hours:02d}:{minutes:02d}:{secondsInt:02d}.{milliseconds:03d}"

    def handleVulnerabilityClick(self, item):
        # Verificar si el ítem es de la columna de descripción
        if item.column() == 3:  # columna de descripción
            text = item.text()
            # Buscar URLs en el texto (formato básico http:// o https://)
            if text.startswith(("http://", "https://")):
                url = text.split()[0]  # Tomar la primera palabra que sería la URL
                response = QMessageBox.question(
                    self,
                    "Abrir URL",
                    f"¿Desea abrir la siguiente URL en su navegador?\n\n{url}\n\nEn ella verá información sobre la vulnerabilidad.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if response == QMessageBox.Yes:
                    QDesktopServices.openUrl(QUrl(url))

    def setup_ui(self):
        mainLayout = QVBoxLayout(self)
        
        # Crear tabs para diferentes secciones
        tabWidget = QTabWidget()
        
        # Tab de información general
        generalTab = QWidget()
        scrollArea = QScrollArea()
        scrollArea.setWidget(generalTab)
        scrollArea.setWidgetResizable(True)
        generalLayout = QGridLayout(generalTab)
        
        generalInfo = self.scanDetails["general"]
        labels = [
            ("📅 Fecha y hora del escaneo:", generalInfo["fecha"]),
            ("🔍 Comando utilizado para escanear:", generalInfo["comando"]),
            ("⏱️ Tiempo de respuesta:", f"{self.formatTime(generalInfo['tiempo_respuesta'])}"),
            ("💻 Sistema operativo detectado:", generalInfo["sistema_operativo"] or "No detectado"),
        ]
        
        for i, (label, value) in enumerate(labels):
            generalLayout.addWidget(QLabel(label), i, 0)
            valueLabel = QLabel(str(value))
            valueLabel.setWordWrap(True)
            generalLayout.addWidget(valueLabel, i, 1)

        # Tab de puertos
        portsTab = QWidget()
        portsLayout = QVBoxLayout(portsTab)
        
        if not self.scanDetails["puertos"]:
            # Si no hay puertos, mostrar mensaje
            noPortsLabel = QLabel("No se encontraron puertos abiertos en este escaneo.")
            noPortsLabel.setAlignment(Qt.AlignCenter)
            portsLayout.addWidget(noPortsLabel)
        else:
            # Crear y configurar la tabla de puertos
            portsTable = QTableWidget()
            portsTable.setColumnCount(4)
            
            # Habilitar ordenamiento
            portsTable.setSortingEnabled(True)
            
            # Crear headers con íconos para la tabla de puertos
            portHeader = QTableWidgetItem("Puerto")
            portHeader.setIcon(QIcon.fromTheme("network-wired"))
            
            protocolHeader = QTableWidgetItem("Protocolo")
            protocolHeader.setIcon(QIcon.fromTheme("emblem-system"))
            
            serviceHeader = QTableWidgetItem("Servicio")
            serviceHeader.setIcon(QIcon.fromTheme("preferences-system-services"))
            
            versionHeader = QTableWidgetItem("Versión")
            versionHeader.setIcon(QIcon.fromTheme("package-x-generic"))
            
            # Establecer headers en la tabla de puertos
            portsTable.setHorizontalHeaderItem(0, portHeader)
            portsTable.setHorizontalHeaderItem(1, protocolHeader)
            portsTable.setHorizontalHeaderItem(2, serviceHeader)
            portsTable.setHorizontalHeaderItem(3, versionHeader)
            
            # Configurar el ancho de las columnas
            header = portsTable.horizontalHeader()
            
            # Puerto
            header.setSectionResizeMode(0, QHeaderView.Interactive)
            portsTable.setColumnWidth(0, 100)
            
            # Protocolo
            header.setSectionResizeMode(1, QHeaderView.Interactive)
            portsTable.setColumnWidth(1, 100)
            
            # Servicio
            header.setSectionResizeMode(2, QHeaderView.Interactive)
            portsTable.setColumnWidth(2, 150)
            
            # Versión
            header.setSectionResizeMode(3, QHeaderView.Interactive)
            portsTable.setColumnWidth(3, 200)
            
            # Configuraciones adicionales
            header.setStretchLastSection(True)
            header.setSortIndicatorShown(True)
            portsTable.setEditTriggers(QTableWidget.NoEditTriggers)
            portsTable.verticalHeader().setDefaultSectionSize(30)
            portsTable.verticalHeader().setMinimumSectionSize(30)

            # Deshabilitar ordenamiento mientras se agregan items
            portsTable.setSortingEnabled(False)
            for port in self.scanDetails["puertos"]:
                row = portsTable.rowCount()
                portsTable.insertRow(row)
                
                # Puerto (ordenable numéricamente)
                portItem = QTableWidgetItem()
                portItem.setData(Qt.DisplayRole, str(port["puerto"]))
                portItem.setData(Qt.UserRole, int(port["puerto"]))
                portsTable.setItem(row, 0, portItem)
                
                # Los demás campos ordenables como texto
                portsTable.setItem(row, 1, QTableWidgetItem(port["protocolo"]))
                portsTable.setItem(row, 2, QTableWidgetItem(port["servicio"]))
                portsTable.setItem(row, 3, QTableWidgetItem(port["version"]))
            
            # Reactivar ordenamiento
            portsTable.setSortingEnabled(True)
            
            portsLayout.addWidget(portsTable)

        # Tab de vulnerabilidades
        vulnsTab = QWidget()
        vulnsLayout = QVBoxLayout(vulnsTab)
        
        if not self.scanDetails["vulnerabilidades"]:
            # Si no hay vulnerabilidades, mostrar mensaje
            noVulnsLabel = QLabel("No se encontraron vulnerabilidades en este escaneo.")
            noVulnsLabel.setAlignment(Qt.AlignCenter)
            vulnsLayout.addWidget(noVulnsLabel)
        else:
            # Crear y configurar la tabla de vulnerabilidades
            vulnsTable = QTableWidget()
            vulnsTable.setColumnCount(4)
            
            # Habilitar ordenamiento
            vulnsTable.setSortingEnabled(True)
            
            # Crear headers con íconos para la tabla de vulnerabilidades
            vulnPortHeader = QTableWidgetItem("Puerto")
            vulnPortHeader.setIcon(QIcon.fromTheme("network-wired"))
            
            vulnProtocolHeader = QTableWidgetItem("Protocolo")
            vulnProtocolHeader.setIcon(QIcon.fromTheme("emblem-system"))
            
            exploitableHeader = QTableWidgetItem("Explotable")
            exploitableHeader.setIcon(QIcon.fromTheme("security-low"))
            
            descriptionHeader = QTableWidgetItem("Descripción")
            descriptionHeader.setIcon(QIcon.fromTheme("dialog-warning"))
            
            # Establecer headers en la tabla de vulnerabilidades
            vulnsTable.setHorizontalHeaderItem(0, vulnPortHeader)
            vulnsTable.setHorizontalHeaderItem(1, vulnProtocolHeader)
            vulnsTable.setHorizontalHeaderItem(2, exploitableHeader)
            vulnsTable.setHorizontalHeaderItem(3, descriptionHeader)
            
            # Configurar el ancho de las columnas
            header = vulnsTable.horizontalHeader()
            
            # Puerto
            header.setSectionResizeMode(0, QHeaderView.Interactive)
            vulnsTable.setColumnWidth(0, 100)
            
            # Protocolo
            header.setSectionResizeMode(1, QHeaderView.Interactive)
            vulnsTable.setColumnWidth(1, 100)
            
            # Explotable
            header.setSectionResizeMode(2, QHeaderView.Interactive)
            vulnsTable.setColumnWidth(2, 110)
            
            # Descripción (con URLs clicables)
            header.setSectionResizeMode(3, QHeaderView.Interactive)
            vulnsTable.setColumnWidth(3, 390)
            
            # Configuraciones adicionales
            header.setStretchLastSection(True)
            header.setSortIndicatorShown(True)
            vulnsTable.setEditTriggers(QTableWidget.NoEditTriggers)
            vulnsTable.verticalHeader().setDefaultSectionSize(30)
            vulnsTable.verticalHeader().setMinimumSectionSize(30)
            
            # Conectar el evento de clic
            vulnsTable.itemClicked.connect(self.handleVulnerabilityClick)
            
            # Deshabilitar ordenamiento mientras se agregan items
            vulnsTable.setSortingEnabled(False)
            for vuln in self.scanDetails["vulnerabilidades"]:
                row = vulnsTable.rowCount()
                vulnsTable.insertRow(row)
                
                # Puerto (ordenable numéricamente)
                portItem = QTableWidgetItem()
                portItem.setData(Qt.DisplayRole, str(vuln["puerto"]))
                portItem.setData(Qt.UserRole, int(vuln["puerto"]))
                vulnsTable.setItem(row, 0, portItem)
                
                # Protocolo
                vulnsTable.setItem(row, 1, QTableWidgetItem(vuln["protocolo"]))
                
                # Explotable (ordenable)
                explotableItem = QTableWidgetItem()
                explotableItem.setData(Qt.DisplayRole, "Sí" if vuln["explotable"] else "No")
                explotableItem.setData(Qt.UserRole, 1 if vuln["explotable"] else 0)
                vulnsTable.setItem(row, 2, explotableItem)
                
                # Crear ítem de descripción con URL clicable
                descItem = QTableWidgetItem(vuln["descripcion"])
                if vuln["descripcion"].startswith(("http://", "https://")):
                    descItem.setForeground(Qt.blue)
                    descItem.setToolTip("Haz clic para abrir en el navegador")
                vulnsTable.setItem(row, 3, descItem)
            
            # Reactivar ordenamiento
            vulnsTable.setSortingEnabled(True)
            
            vulnsLayout.addWidget(vulnsTable)
        
        # Agregar tabs al widget principal
        tabWidget.addTab(scrollArea, "ℹ️ Información general")
        tabWidget.addTab(portsTab, "🔌 Puertos")
        tabWidget.addTab(vulnsTab, "⚠️ Vulnerabilidades")
        
        mainLayout.addWidget(tabWidget)
        
        # Botón de cerrar
        closeButton = QPushButton("Cerrar")
        closeButton.clicked.connect(self.accept)
        mainLayout.addWidget(closeButton)
