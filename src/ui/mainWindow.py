from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QPushButton, QLineEdit, QTextEdit, QComboBox,
                             QLabel, QFrame, QTabWidget, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QMessageBox, QFileDialog, QDialog)
from PySide6.QtGui import QPalette, QRegularExpressionValidator, QIcon
from PySide6.QtCore import QRegularExpression, Qt
from core.constants import DEFAULT_TARGET
from core.scanner import NmapScanner, ScanResultProcessor
from core.records import RecordManager
from core.remote_db import RemoteDBManager
from ui.scanDetails import ScanDetailsDialog
from ui.datePickerDialog import DatePickerDialog
from ui.remoteConfigDialog import RemoteConfigDialog
from ui.remoteStatusDialog import RemoteStatusDialog
from ui.remoteFileSelector import RemoteFileSelector
from styles.themes import DARK_THEME, LIGHT_THEME
import sqlite3

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PICIR")
        self.setGeometry(100, 100, 800, 600)
        
        # Lista para mantener referencias a las ventanas de detalles
        self.detailWindows = []
        
        # Gestor de conexión remota
        self.remote_manager = RemoteDBManager()
        
        # Detectar tema del sistema
        app = QApplication.instance()
        self.isDarkTheme = app.palette().color(QPalette.Window).lightness() < 128
        self.setStyleSheet(DARK_THEME if self.isDarkTheme else LIGHT_THEME)

        self._setupUi()

    def _setupUi(self):
        # Widget y layout principal
        mainWidget = QWidget()
        mainLayout = QVBoxLayout()
        mainWidget.setLayout(mainLayout)

        # Configurar barra superior
        self._setupTopBar(mainLayout)

        # Configurar pestañas
        self.tabWidget = QTabWidget()
        mainLayout.addWidget(self.tabWidget)

        # Configurar pestaña de escaneo
        self._setupScanTab()

        # Configurar pestaña de registros
        self._setupRecordsTab()

        # Configurar pestaña de honeypot
        self._setupHoneypotTab()

        self.setCentralWidget(mainWidget)

    def _setupTopBar(self, mainLayout):
        topBar = QHBoxLayout()
        
        # Selector de tema
        themeLabel = QLabel("Tema:")
        self.themeCombo = QComboBox()
        self.themeCombo.setObjectName("themeSelector")
        self.themeCombo.addItems(["Sistema", "Claro", "Oscuro"])
        self.themeCombo.setCurrentText("Sistema")
        self.themeCombo.currentTextChanged.connect(self.changeTheme)
        topBar.addWidget(themeLabel)
        topBar.addWidget(self.themeCombo)
        
        # Botón de sincronización remota
        self.remoteButton = QPushButton(" Conexión remota")
        self.remoteButton.setIcon(QIcon.fromTheme("network-server"))
        self.remoteButton.clicked.connect(self.showRemoteConfig)
        topBar.addWidget(self.remoteButton)
        
        topBar.addStretch()
        mainLayout.addLayout(topBar)

    def _setupScanTab(self):
        scanTab = QWidget()
        scanLayout = QVBoxLayout()
        scanTab.setLayout(scanLayout)

        # Sección de entrada para el escaneo
        inputFrame = QFrame()
        inputLayout = QVBoxLayout()
        inputFrame.setLayout(inputLayout)

        # Target input
        targetLabel = QLabel("Objetivo del escaneo:")
        self.targetInput = QLineEdit()
        self.targetInput.setPlaceholderText(f"Ingrese la IP, rango de IPs o el nombre del host (Si deja vacío se usará: {DEFAULT_TARGET})")
        inputLayout.addWidget(targetLabel)
        inputLayout.addWidget(self.targetInput)

        # Tipo de escaneo
        scanTypeLabel = QLabel("Tipo de escaneo:")
        self.scanTypeCombo = QComboBox()
        self.scanTypeCombo.addItems(["TCP", "UDP"])
        inputLayout.addWidget(scanTypeLabel)
        inputLayout.addWidget(self.scanTypeCombo)

        # Preview del comando
        previewFrameLabel = QLabel("Vista previa del comando:")
        self.previewLabel = QLabel()
        self.previewLabel.setObjectName("previewLabel")
        self.previewLabel.setWordWrap(True)
        inputLayout.addWidget(previewFrameLabel)
        inputLayout.addWidget(self.previewLabel)

        # Conectar señales para actualizar el preview
        self.targetInput.textChanged.connect(self.updateNmapCommand)
        self.scanTypeCombo.currentTextChanged.connect(self.updateNmapCommand)
        
        # Botón de escaneo
        self.scanButton = QPushButton("Iniciar escaneo")
        self.scanButton.clicked.connect(self.beginScan)
        inputLayout.addWidget(self.scanButton)

        scanLayout.addWidget(inputFrame)

        # Área de resultados del escaneo
        resultsLabel = QLabel("Resultados del escaneo:")
        self.resultArea = QTextEdit()
        self.resultArea.setReadOnly(True)
        scanLayout.addWidget(resultsLabel)
        scanLayout.addWidget(self.resultArea)

        # Actualizar el preview inicial
        self.updateNmapCommand()

        # Añadir la pestaña de escaneo
        self.tabWidget.addTab(scanTab, "Escaneo")

    def _setupRecordsTab(self):
        recordsTab = QWidget()
        recordsLayout = QVBoxLayout()
        recordsTab.setLayout(recordsLayout)

        # Controles para filtrar registros
        filterFrame = QFrame()
        filterLayout = QHBoxLayout()
        filterFrame.setLayout(filterLayout)
        
        # Botón de refrescar
        refreshLayout = QVBoxLayout()
        refreshLabel = QLabel("Actualizar:")
        self.refreshBtn = QPushButton(" Recargar")
        self.refreshBtn.clicked.connect(self.refreshRecords)
        self.refreshBtn.setIcon(QIcon.fromTheme("view-refresh"))
        
        refreshLayout.addWidget(refreshLabel)
        refreshLayout.addWidget(self.refreshBtn)
        filterLayout.addLayout(refreshLayout)

        # Botón y etiqueta para filtrar por fecha
        dateFilterLayout = QVBoxLayout()
        dateLabel = QLabel("Filtrar por fecha:")
        self.dateFilterBtn = QPushButton("Seleccionar fecha")
        self.dateFilterBtn.clicked.connect(self.showDatePicker)
        self.selectedDate = None
        
        dateFilterLayout.addWidget(dateLabel)
        dateFilterLayout.addWidget(self.dateFilterBtn)
        filterLayout.addLayout(dateFilterLayout)

        # Filtro de IP
        ipFilterLayout = QVBoxLayout()
        ipLabel = QLabel("Filtrar por IP del host:")
        self.ipFilter = QLineEdit()
        self.ipFilter.setPlaceholderText("Ej: 192.168.1.1")
        
        # Validador para direcciones IP (parciales o completas)
        ipRegex = QRegularExpression(r"^(\d{1,3}\.){0,3}\d{0,3}$")
        self.ipFilter.setValidator(QRegularExpressionValidator(ipRegex))
        self.ipFilter.textChanged.connect(self.searchRecords)
        
        ipFilterLayout.addWidget(ipLabel)
        ipFilterLayout.addWidget(self.ipFilter)
        filterLayout.addLayout(ipFilterLayout)

        recordsLayout.addWidget(filterFrame)

        # Tabla de resultados
        self.recordsTable = QTableWidget()
        self.recordsTable.setColumnCount(5)
        
        # Crear items de encabezado con iconos
        dateHeader = QTableWidgetItem("Fecha y hora")
        dateHeader.setIcon(QIcon.fromTheme("calendar"))
        
        ipHeader = QTableWidgetItem("IP del host")
        ipHeader.setIcon(QIcon.fromTheme("network-server"))
        
        portsHeader = QTableWidgetItem("Puertos abiertos")
        portsHeader.setIcon(QIcon.fromTheme("network-transmit"))
        
        vulnsHeader = QTableWidgetItem("Vulnerabilidades")
        vulnsHeader.setIcon(QIcon.fromTheme("security-high"))
        
        detailsHeader = QTableWidgetItem("Detalles")
        detailsHeader.setIcon(QIcon.fromTheme("dialog-information"))
        
        # Establecer items de encabezado
        self.recordsTable.setHorizontalHeaderItem(0, dateHeader)
        self.recordsTable.setHorizontalHeaderItem(1, ipHeader)
        self.recordsTable.setHorizontalHeaderItem(2, portsHeader)
        self.recordsTable.setHorizontalHeaderItem(3, vulnsHeader)
        self.recordsTable.setHorizontalHeaderItem(4, detailsHeader)
        
        # Configurar el ancho de las columnas
        header = self.recordsTable.horizontalHeader()
        
        # Habilitar ordenamiento
        self.recordsTable.setSortingEnabled(True)
        header.setSortIndicatorShown(True)
        header.sortIndicatorChanged.connect(self.onTableSort)
        
        # Fecha y hora
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.recordsTable.setColumnWidth(0, 160)
        
        # IP host
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        self.recordsTable.setColumnWidth(1, 120)
        
        # Puertos abiertos
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        self.recordsTable.setColumnWidth(2, 150)
        
        # Vulnerabilidades
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        self.recordsTable.setColumnWidth(3, 150)
        
        # Botón de detalles
        header.setSectionResizeMode(4, QHeaderView.Interactive)
        self.recordsTable.setColumnWidth(4, 100)
        
        # Permitir que el usuario ajuste el tamaño de las columnas
        header.setStretchLastSection(True)
        self.recordsTable.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Ajustar altura de las filas
        self.recordsTable.verticalHeader().setDefaultSectionSize(30)
        self.recordsTable.verticalHeader().setMinimumSectionSize(30)
        
        recordsLayout.addWidget(self.recordsTable)

        # Añadir la pestaña de registros
        self.tabWidget.addTab(recordsTab, "Registros")

        # Realizar búsqueda inicial
        self.searchRecords()

    def _setupHoneypotTab(self):
        """Configura la pestaña de registros del honeypot"""
        honeypotTab = QWidget()
        layout = QVBoxLayout(honeypotTab)
        
        # Frame superior para controles
        controlFrame = QFrame()
        controlLayout = QHBoxLayout(controlFrame)
        
        # Etiqueta para mostrar el archivo seleccionado
        self.honeypotDbLabel = QLabel("No hay base de datos seleccionada")
        controlLayout.addWidget(self.honeypotDbLabel)
        
        # Botón para seleccionar archivo
        self.selectHoneypotButton = QPushButton("Seleccionar base de datos")
        self.selectHoneypotButton.clicked.connect(self._selectHoneypotDb)
        controlLayout.addWidget(self.selectHoneypotButton)
        
        layout.addWidget(controlFrame)
        
        # Tabla de registros
        self.honeypotTable = QTableWidget()
        self.honeypotTable.setEditTriggers(QTableWidget.NoEditTriggers)  # Solo lectura
        layout.addWidget(self.honeypotTable)
        
        # Añadir la pestaña
        self.tabWidget.addTab(honeypotTab, "Registros Honeypot")

    def showDatePicker(self):
        try:
            # Obtener fechas disponibles
            available_dates = RecordManager.getAvailableDates()
            
            # Crear el diálogo
            dialog = DatePickerDialog(available_dates, self)
            dialog.dateSelected.connect(self.onDateSelected)
            
            # Calcular la posición para el diálogo
            button_pos = self.dateFilterBtn.mapToGlobal(self.dateFilterBtn.rect().bottomLeft())
            dialog.move(button_pos)
            
            # Mostrar el diálogo
            dialog.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al cargar fechas: {str(e)}")

    def onDateSelected(self, date):
        self.selectedDate = date if date else None
        # Actualizar el texto del botón
        if self.selectedDate:
            self.dateFilterBtn.setText(f"Fecha: {self.selectedDate}")
        else:
            self.dateFilterBtn.setText("Todas las fechas")
        # Actualizar la búsqueda
        self.searchRecords()

    def changeTheme(self, theme):
        if theme == "Sistema":
            app = QApplication.instance()
            self.isDarkTheme = app.palette().color(QPalette.Window).lightness() < 128
        else:
            self.isDarkTheme = theme == "Oscuro"
        
        self.setStyleSheet(DARK_THEME if self.isDarkTheme else LIGHT_THEME)

    def updateNmapCommand(self):
        target = self.targetInput.text().strip() or DEFAULT_TARGET
        scanType = "UDP" if self.scanTypeCombo.currentText() == "UDP" else "TCP"
        
        # Base de opciones para el escaneo
        baseOptions = "-T5 --script vulners"
        
        # Opciones específicas según el tipo de escaneo
        if scanType == "UDP":
            options = f"-sUV -O {baseOptions}"  # UDP scan with version detection
        else:
            options = f"-sV -O {baseOptions}"   # TCP scan with version detection
            
        # Actualizar el texto del comando
        command = f"nmap {options} {target}"
        self.previewLabel.setText(command)

    def beginScan(self):
        # Deshabilitar botón durante el escaneo
        self.scanButton.setEnabled(False)
        self.scanButton.setText("Escaneando...")
        QApplication.processEvents()  # Actualizar la interfaz

        try:
            target = self.targetInput.text().strip() or DEFAULT_TARGET
            scanType = "UDP" if self.scanTypeCombo.currentText() == "UDP" else "TCP"

            # Realizar el escaneo
            scanResults = NmapScanner.scanTarget(
                target, 
                scanType,
                lambda msg: self.resultArea.append(msg)
            )

            if scanResults:
                # Procesar resultados
                processor = ScanResultProcessor(
                    scanResults,
                    lambda msg: self.resultArea.append(msg)
                )
                processor.processResults()

        except Exception as e:
            self.resultArea.append(f"❌ Error durante el escaneo: {e}")
        finally:
            # Restaurar el botón
            self.scanButton.setEnabled(True)
            self.scanButton.setText("Iniciar escaneo")

    def refreshRecords(self):
        """Limpia los filtros y actualiza la lista de registros"""
        # Resetear filtro de fecha
        self.selectedDate = None
        self.dateFilterBtn.setText("Seleccionar fecha")
        
        # Limpiar filtro de IP
        self.ipFilter.clear()
        
        # Actualizar registros
        self.searchRecords()

    def searchRecords(self):
        try:
            # Limpiar tabla actual
            self.recordsTable.setRowCount(0)

            # Obtener filtros
            dateFilter = self.selectedDate if self.selectedDate else None
            ipFilter = self.ipFilter.text().strip()

            # Buscar registros
            records = RecordManager.searchRecords(dateFilter, ipFilter)

            # Llenar tabla con resultados
            for record in records:
                row = self.recordsTable.rowCount()
                self.recordsTable.insertRow(row)
                
                # Deshabilitar ordenamiento mientras se agregan items
                self.recordsTable.setSortingEnabled(False)
                
                # Añadir datos
                # Fecha (ordenable por fecha/hora)
                fechaItem = QTableWidgetItem(record["fecha"])
                fechaItem.setData(Qt.UserRole, record["fecha"])  # Para ordenamiento correcto
                self.recordsTable.setItem(row, 0, fechaItem)
                
                # IP (ordenable por octetos)
                ipItem = QTableWidgetItem(record["ip_host"])
                # Convertir IP a número para ordenamiento correcto
                ip_value = sum(int(x) * (256 ** (3-i)) for i, x in enumerate(record["ip_host"].split('.')))
                ipItem.setData(Qt.UserRole, ip_value)
                self.recordsTable.setItem(row, 1, ipItem)
                
                # Puertos (ordenable numéricamente)
                puertosItem = QTableWidgetItem()
                puertosItem.setData(Qt.DisplayRole, str(record["puertos_abiertos"]))
                puertosItem.setData(Qt.UserRole, int(record["puertos_abiertos"]))
                self.recordsTable.setItem(row, 2, puertosItem)
                
                # Vulnerabilidades (ordenable numéricamente)
                vulnsItem = QTableWidgetItem()
                vulnsItem.setData(Qt.DisplayRole, str(record["vulnerabilidades"]))
                vulnsItem.setData(Qt.UserRole, int(record["vulnerabilidades"]))
                self.recordsTable.setItem(row, 3, vulnsItem)
                
                # Reactivar ordenamiento
                self.recordsTable.setSortingEnabled(True)
                
                # Botón de detalles
                detailsButton = QPushButton("Ver más detalles")
                detailsButton.setFixedHeight(27)
                detailsButton.setStyleSheet("""
                    QPushButton {
                        padding: 2px 8px;  /* padding vertical: 2px, horizontal: 8px */
                    }
                """)
                detailsButton.clicked.connect(
                    lambda checked, r=record: self.showScanDetails(r["id"], r["ip_host"])
                )
                self.recordsTable.setCellWidget(row, 4, detailsButton)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al buscar registros: {str(e)}")

    def onTableSort(self, logicalIndex, order):
        """Maneja el evento de ordenamiento de la tabla"""
        # Guardar el estado de ordenamiento actual
        self.recordsTable.horizontalHeader().setSortIndicator(logicalIndex, order)

    def showScanDetails(self, scanId: int, hostIp: str):
        try:
            # Limpiar las ventanas cerradas de la lista
            self.detailWindows = [w for w in self.detailWindows if not w.isHidden()]
            
            # Obtener detalles del escaneo
            scanDetails = RecordManager.getScanDetails(scanId, hostIp)
            
            # Crear diálogo como ventana independiente
            dialog = ScanDetailsDialog(scanDetails)  # No pasamos el parent
            dialog.setWindowTitle(f"Detalles del escaneo - {hostIp}")
            
            # Configurar como ventana independiente
            dialog.setWindowFlags(
                dialog.windowFlags() | 
                Qt.WindowType.Window |  # Hacer que sea una ventana independiente
                Qt.WindowType.WindowSystemMenuHint |  # Agregar menú de sistema
                Qt.WindowType.WindowMinMaxButtonsHint  # Permitir minimizar/maximizar
            )
            
            # Conectar la señal destroyed para limpieza automática
            dialog.destroyed.connect(lambda: self.detailWindows.remove(dialog) 
                                  if dialog in self.detailWindows else None)
            
            # Agregar a la lista de ventanas activas
            self.detailWindows.append(dialog)
            
            # Mostrar diálogo de forma no modal
            dialog.show()  # Usar show() en lugar de exec_() para no bloquear
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al mostrar detalles: {str(e)}")

    def openRemoteConfig(self):
        try:
            # Crear diálogo de configuración remota
            dialog = RemoteConfigDialog(self)
            dialog.setWindowTitle("Configuración Remota")
            
            # Mostrar diálogo de forma modal
            dialog.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error al abrir configuración remota: {str(e)}")

    def showRemoteConfig(self):
        """Muestra el diálogo de configuración/estado de conexión remota"""
        # Verificar si ya hay una conexión activa intentando usar el SFTP
        try:
            if self.remote_manager.sftp:
                try:
                    # Intentar una operación simple para verificar la conexión
                    self.remote_manager.sftp.stat('.')
                    # Si llegamos aquí, la conexión está activa
                    dialog = RemoteStatusDialog(self.remote_manager, self)
                    dialog.exec_()
                    return
                except Exception:
                    # La conexión está rota, limpiarla
                    self.remote_manager.disconnect()
            
            # No hay conexión o se perdió, mostrar diálogo de configuración
            dialog = RemoteConfigDialog(self)
            # Establecer el RemoteDBManager y conectar señales
            dialog.setRemoteManager(self.remote_manager)
            dialog.connectionEstablished.connect(lambda: self.remote_manager.syncProgress.emit("✅ Conexión establecida"))
            dialog.exec_()
            
        except Exception as e:
            # Si hay cualquier error inesperado
            QMessageBox.critical(self, "Error", f"Error al verificar la conexión: {str(e)}")
            self.remote_manager.disconnect()

    def _selectHoneypotDb(self):
        """Abre el diálogo para seleccionar una base de datos remota del honeypot"""
        try:
            if not self.remote_manager.isConnected():
                QMessageBox.warning(
                    self,
                    "Conexión remota requerida",
                    "Debe establecer una conexión remota primero para acceder a las bases de datos"
                )
                self.showRemoteConfig()
                return
            
            dialog = RemoteFileSelector(self.remote_manager, self)
            dialog.fileSelected.connect(self._loadHoneypotDb)
            
            # Mostrar el diálogo
            dialog.exec_()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Error al abrir el selector de archivos: {str(e)}"
            )

    def _loadHoneypotDb(self, remote_path):
        """Carga una base de datos del honeypot desde la ruta remota especificada"""
        try:
            # Crear directorio temporal si no existe
            import tempfile
            import os
            temp_dir = os.path.join(tempfile.gettempdir(), "picir_honeypot")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Verificar que sea un archivo SQLite válido
            filename = os.path.basename(remote_path)
            if not self._is_sqlite_file(filename):
                raise Exception("El archivo seleccionado no es una base de datos SQLite válida")
            
            # Generar nombre para archivo temporal local
            local_path = os.path.join(temp_dir, filename)
            
            # Descargar el archivo usando el SFTP
            try:
                if not self.remote_manager.ssh:
                    raise Exception("No hay conexión SSH activa")
                sftp = self.remote_manager.ssh.open_sftp()
                sftp.get(remote_path, local_path)
                sftp.close()
            except Exception as e:
                raise Exception(f"Error al descargar el archivo: {str(e)}")
            
            # Conectar a la base de datos
            conn = sqlite3.connect(local_path)
            cursor = conn.cursor()
            
            # Primero verificar si las tablas existen
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name IN ('escaneos', 'escaneos_host', 'escaneos_puertos', 'vulnerabilidades');
            """)
            existing_tables = [row[0] for row in cursor.fetchall()]
            
            if 'escaneos' in existing_tables and 'escaneos_host' in existing_tables:
                # Consulta JOIN para obtener toda la información relacionada
                query = """
                    SELECT 
                        e.fecha_hora,
                        h.id_host,
                        h.direccion_mac,
                        h.sistema_operativo,
                        e.comando,
                        e.tiempo_respuesta,
                        p.puerto,
                        p.protocolo,
                        p.estado,
                        p.servicio,
                        p.version,
                        v.codigo_vulnerabilidad,
                        v.explotable,
                        v.cvss,
                        v.descripcion
                    FROM escaneos e
                    JOIN escaneos_host h ON e.id = h.id_escaneo
                    LEFT JOIN escaneos_puertos p ON h.id_escaneo = p.id_escaneo AND h.id_host = p.id_host
                    LEFT JOIN vulnerabilidades v ON p.id_escaneo = v.id_escaneo 
                        AND p.id_host = v.id_host 
                        AND p.puerto = v.puerto 
                        AND p.protocolo = v.protocolo
                    ORDER BY e.fecha_hora DESC, h.id_host, p.puerto;
                """
            else:
                # Si no existen las tablas, hacer una consulta simple
                table_name = cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()[0]
                query = f"SELECT * FROM {table_name};"
            
            cursor.execute(query)
            records = cursor.fetchall()
            
            # Definir las columnas que queremos mostrar
            columns = [
                "Fecha y Hora", "Host", "MAC", "Sistema Operativo",
                "Puerto", "Protocolo", "Estado", "Servicio", "Versión",
                "Vulnerabilidad", "CVSS", "Explotable"
            ]
            
            # Configurar la tabla
            self.honeypotTable.setColumnCount(len(columns))
            self.honeypotTable.setHorizontalHeaderLabels(columns)
            
            # Ajustar tamaño y comportamiento de las columnas
            header = self.honeypotTable.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            
            # Establecer anchos iniciales para las columnas
            column_widths = {
                0: 150,  # Fecha y Hora
                1: 120,  # Host
                2: 120,  # MAC
                3: 150,  # Sistema Operativo
                4: 70,   # Puerto
                5: 80,   # Protocolo
                6: 80,   # Estado
                7: 100,  # Servicio
                8: 100,  # Versión
                9: 150,  # Vulnerabilidad
                10: 70,  # CVSS
                11: 80,  # Explotable
            }
            
            for col, width in column_widths.items():
                self.honeypotTable.setColumnWidth(col, width)
            
            # Permitir ordenamiento
            self.honeypotTable.setSortingEnabled(True)
            header.setSortIndicatorShown(True)
            
            # Eliminar filas vacías
            for row in range(self.honeypotTable.rowCount() - 1, -1, -1):
                is_empty = True
                for col in range(self.honeypotTable.columnCount()):
                    item = self.honeypotTable.item(row, col)
                    if item and item.text().strip():
                        is_empty = False
                        break
                if is_empty:
                    self.honeypotTable.removeRow(row)
            
            # Procesar y mostrar los datos
            current_row = -1
            current_host = None
            self.honeypotTable.setRowCount(len(records))
            
            if 'escaneos' in existing_tables and 'escaneos_host' in existing_tables:
                for record in records:
                    # Si es un nuevo host o la primera fila
                    if current_host != record[1]:  # record[1] es id_host
                        current_row += 1
                        current_host = record[1]
                        
                        # Fecha y Hora
                        self.honeypotTable.setItem(current_row, 0, QTableWidgetItem(str(record[0] or "")))
                        # Host (IP)
                        self.honeypotTable.setItem(current_row, 1, QTableWidgetItem(str(record[1] or "")))
                        # MAC
                        mac_addr = str(record[2] or "No detectada").strip()
                        self.honeypotTable.setItem(current_row, 2, QTableWidgetItem(mac_addr))
                        # Sistema Operativo
                        os_info = str(record[3] or "No detectado").strip()
                        self.honeypotTable.setItem(current_row, 3, QTableWidgetItem(os_info))
                        # Puerto
                        self.honeypotTable.setItem(current_row, 4, QTableWidgetItem(str(record[6] or "")))
                        # Protocolo
                        self.honeypotTable.setItem(current_row, 5, QTableWidgetItem(str(record[7] or "")))
                        # Estado
                        self.honeypotTable.setItem(current_row, 6, QTableWidgetItem(str(record[8] or "")))
                        # Servicio
                        self.honeypotTable.setItem(current_row, 7, QTableWidgetItem(str(record[9] or "")))
                        # Versión
                        self.honeypotTable.setItem(current_row, 8, QTableWidgetItem(str(record[10] or "")))
                        # Vulnerabilidad
                        self.honeypotTable.setItem(current_row, 9, QTableWidgetItem(str(record[11] or "")))
                        # CVSS
                        self.honeypotTable.setItem(current_row, 10, QTableWidgetItem(str(record[13] or "")))
                        # Explotable
                        explotable = "Sí" if record[12] else "No" if record[12] is not None else ""
                        self.honeypotTable.setItem(current_row, 11, QTableWidgetItem(explotable))
            else:
                # Si no es una base de datos de escaneos, mostrar los datos tal cual
                for row, record in enumerate(records):
                    for col, value in enumerate(record):
                        self.honeypotTable.setItem(row, col, QTableWidgetItem(str(value or "")))
            
            # Ajustar tamaño de columnas
            self.honeypotTable.resizeColumnsToContents()
            
            # Actualizar etiqueta
            self.honeypotDbLabel.setText(f"Base de datos: {os.path.basename(remote_path)}")
            
            # Limpiar recursos
            cursor.close()
            conn.close()
            
            # Eliminar archivo temporal
            os.remove(local_path)
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Error al cargar la base de datos del honeypot: {str(e)}"
            )

    def _is_sqlite_file(self, filename):
        """Verifica si un nombre de archivo tiene una extensión válida de SQLite"""
        return filename.lower().endswith(('.db', '.sqlite', '.db3', '.sqlite3'))
