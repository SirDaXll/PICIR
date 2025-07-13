from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QPushButton, QLineEdit, QTextEdit, QComboBox,
                             QLabel, QFrame, QTabWidget, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QMessageBox, QAbstractItemView, QDialog,
                             QTreeWidget, QTabBar, QSpinBox, QDateEdit)
from PySide6.QtGui import (QRegularExpressionValidator, QIcon, QCursor,
                           QPalette, QColor)
from PySide6.QtCore import QRegularExpression, Qt, QSize
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
from datetime import datetime
import tempfile
import os
import sqlite3

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PICIR")
        self.setGeometry(100, 100, 800, 600)
        
        # Habilitar minimizar/maximizar
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowMinMaxButtonsHint |
            Qt.WindowType.WindowCloseButtonHint
        )
        
        # Establecer el ícono de la aplicación
        icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources", "icons", "app.svg")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        
        # Lista para mantener referencias a las ventanas de detalles
        self.detailWindows = []
        
        # Gestor de conexión remota
        self.remote_manager = RemoteDBManager()
        
        # Path base para los iconos
        self.icons_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources", "icons")
        
        # Inicializar con tema claro por defecto
        self.current_theme = "light"
        self.setStyleSheet(LIGHT_THEME)
        
        # Crear el botón de tema como un QPushButton con solo icono
        self.theme_button = QPushButton()
        self.theme_button.setFixedSize(32, 32)
        self.theme_button.setIconSize(QSize(24, 24))
        self.theme_button.clicked.connect(self.toggle_theme)
        self.theme_button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.theme_button.setStyleSheet("""
            QPushButton {
                border: none;
                background: transparent;
                padding: 4px;
            }
            QPushButton:hover {
                background: rgba(128, 128, 128, 0.2);
                border-radius: 16px;
            }
        """)
        
        # Actualizar el tema inicial y el icono
        self.current_theme = "light"
        self.update_theme_button()

        self._setup_ui()

    def _setup_ui(self):
        # Widget y layout principal
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Configurar barra superior
        self._setup_top_bar(main_layout)

        # Configurar pestañas
        self.tabWidget = QTabWidget()
        main_layout.addWidget(self.tabWidget)

        # Configurar pestaña de escaneo
        self._setup_scan_tab()

        # Configurar pestaña de registros
        self._setup_records_tab()

        # Configurar pestaña de honeypot
        self._setup_honeypot_tab()

        self.setCentralWidget(main_widget)

    def _setup_top_bar(self, main_layout):
        top_bar = QHBoxLayout()
        
        # Lado izquierdo: Botón de tema
        top_bar.addWidget(self.theme_button)
        
        # Espacio flexible en el medio
        top_bar.addStretch()
        
        # Lado derecho: Botón de sincronización remota
        self.remoteButton = QPushButton(" Conexión remota")
        self.remoteButton.setIcon(QIcon.fromTheme("network-server"))
        self.remoteButton.clicked.connect(self.show_remote_config)
        top_bar.addWidget(self.remoteButton)
        
        main_layout.addLayout(top_bar)

    def _setup_scan_tab(self):
        scan_tab = QWidget()
        scan_layout = QVBoxLayout()
        scan_tab.setLayout(scan_layout)

        # Sección de entrada para el escaneo
        input_frame = QFrame()
        input_layout = QVBoxLayout()
        input_frame.setLayout(input_layout)

        # Target input
        target_label = QLabel("Objetivo del escaneo:")
        self.targetInput = QLineEdit()
        self.targetInput.setPlaceholderText(f"Ingrese la IP, rango de IPs o el nombre del host (Si deja vacío se usará: {DEFAULT_TARGET})")
        input_layout.addWidget(target_label)
        input_layout.addWidget(self.targetInput)

        # Tipo de escaneo
        scan_type_label = QLabel("Tipo de escaneo:")
        self.scanTypeCombo = QComboBox()
        self.scanTypeCombo.addItems(["TCP", "UDP"])
        input_layout.addWidget(scan_type_label)
        input_layout.addWidget(self.scanTypeCombo)

        # Preview del comando
        preview_frame_label = QLabel("Vista previa del comando:")
        self.previewLabel = QLabel()
        self.previewLabel.setObjectName("previewLabel")
        self.previewLabel.setWordWrap(True)
        input_layout.addWidget(preview_frame_label)
        input_layout.addWidget(self.previewLabel)

        # Conectar señales para actualizar el preview
        self.targetInput.textChanged.connect(self.update_nmap_command)
        self.scanTypeCombo.currentTextChanged.connect(self.update_nmap_command)
        
        # Botón de escaneo
        self.scanButton = QPushButton("Iniciar escaneo")
        self.scanButton.clicked.connect(self.begin_scan)
        input_layout.addWidget(self.scanButton)

        scan_layout.addWidget(input_frame)

        # Área de resultados del escaneo
        results_label = QLabel("Resultados del escaneo:")
        self.resultArea = QTextEdit()
        self.resultArea.setReadOnly(True)
        scan_layout.addWidget(results_label)
        scan_layout.addWidget(self.resultArea)

        # Actualizar el preview inicial
        self.update_nmap_command()

        # Añadir la pestaña de escaneo
        self.tabWidget.addTab(scan_tab, "Escaneo")

    def _setup_records_tab(self):
        records_tab = QWidget()
        records_layout = QVBoxLayout()
        records_tab.setLayout(records_layout)

        # Controles para filtrar registros
        filter_frame = QFrame()
        filter_layout = QHBoxLayout()
        filter_frame.setLayout(filter_layout)
        
        # Botón de refrescar
        refresh_layout = QVBoxLayout()
        refresh_label = QLabel("Actualizar:")
        self.refreshBtn = QPushButton(" Recargar")
        self.refreshBtn.clicked.connect(self.refresh_records)
        self.refreshBtn.setIcon(QIcon.fromTheme("view-refresh"))
        
        refresh_layout.addWidget(refresh_label)
        refresh_layout.addWidget(self.refreshBtn)
        filter_layout.addLayout(refresh_layout)

        # Botón y etiqueta para filtrar por fecha
        date_filter_layout = QVBoxLayout()
        date_label = QLabel("Filtrar por fecha:")
        self.dateFilterBtn = QPushButton("Seleccionar fecha")
        self.dateFilterBtn.clicked.connect(self.show_date_picker)
        self.selectedDate = None
        
        date_filter_layout.addWidget(date_label)
        date_filter_layout.addWidget(self.dateFilterBtn)
        filter_layout.addLayout(date_filter_layout)

        # Filtro de IP
        ip_filter_layout = QVBoxLayout()
        ip_label = QLabel("Filtrar por IP del host:")
        self.ipFilter = QLineEdit()
        self.ipFilter.setPlaceholderText("Ej: 192.168.1.1")
        
        # Validador para direcciones IP (parciales o completas)
        ip_regex = QRegularExpression(r"^(\d{1,3}\.){0,3}\d{0,3}$")
        self.ipFilter.setValidator(QRegularExpressionValidator(ip_regex))
        self.ipFilter.textChanged.connect(self.search_records)
        
        ip_filter_layout.addWidget(ip_label)
        ip_filter_layout.addWidget(self.ipFilter)
        filter_layout.addLayout(ip_filter_layout)

        records_layout.addWidget(filter_frame)

        # Tabla de resultados
        self.recordsTable = QTableWidget()
        self.recordsTable.setColumnCount(5)
        
        # Crear items de encabezado con iconos
        date_header = QTableWidgetItem("Fecha y hora")
        date_header.setIcon(QIcon.fromTheme("calendar"))
        
        ip_header = QTableWidgetItem("IP del host")
        ip_header.setIcon(QIcon.fromTheme("network-server"))
        
        ports_header = QTableWidgetItem("Puertos abiertos")
        ports_header.setIcon(QIcon.fromTheme("network-transmit"))
        
        vulns_header = QTableWidgetItem("Vulnerabilidades")
        vulns_header.setIcon(QIcon.fromTheme("security-high"))
        
        details_header = QTableWidgetItem("Detalles")
        details_header.setIcon(QIcon.fromTheme("dialog-information"))
        
        # Establecer items de encabezado
        self.recordsTable.setHorizontalHeaderItem(0, date_header)
        self.recordsTable.setHorizontalHeaderItem(1, ip_header)
        self.recordsTable.setHorizontalHeaderItem(2, ports_header)
        self.recordsTable.setHorizontalHeaderItem(3, vulns_header)
        self.recordsTable.setHorizontalHeaderItem(4, details_header)
        
        # Configurar el ancho de las columnas
        header = self.recordsTable.horizontalHeader()
        
        # Habilitar ordenamiento
        self.recordsTable.setSortingEnabled(True)
        header.setSortIndicatorShown(True)
        header.sortIndicatorChanged.connect(self.on_table_sort)
        
        # Fecha y hora
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.recordsTable.setColumnWidth(0, 160)
        
        # IP host
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.recordsTable.setColumnWidth(1, 120)
        
        # Puertos abiertos
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.recordsTable.setColumnWidth(2, 150)
        
        # Vulnerabilidades
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.recordsTable.setColumnWidth(3, 150)
        
        # Botón de detalles
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.recordsTable.setColumnWidth(4, 100)
        
        # Permitir que el usuario ajuste el tamaño de las columnas
        header.setStretchLastSection(True)
        self.recordsTable.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        
        # Ajustar altura de las filas
        self.recordsTable.verticalHeader().setDefaultSectionSize(30)
        self.recordsTable.verticalHeader().setMinimumSectionSize(30)
        
        records_layout.addWidget(self.recordsTable)

        # Añadir la pestaña de registros
        self.tabWidget.addTab(records_tab, "Registros")

        # Realizar búsqueda inicial
        self.search_records()

    def _setup_honeypot_tab(self):
        """Configura la pestaña de registros del honeypot"""
        honeypot_tab = QWidget()
        layout = QVBoxLayout(honeypot_tab)
        
        # Frame superior para controles
        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        
        # Botón de refrescar (izquierda)
        refresh_layout = QVBoxLayout()
        refresh_label = QLabel("Actualizar:")
        self.honeypotRefreshBtn = QPushButton(" Recargar")
        self.honeypotRefreshBtn.setIcon(QIcon.fromTheme("view-refresh"))
        self.honeypotRefreshBtn.clicked.connect(self._refresh_honeypot)
        refresh_layout.addWidget(refresh_label)
        refresh_layout.addWidget(self.honeypotRefreshBtn)
        control_layout.addLayout(refresh_layout)
        
        # Filtro de fecha (centro)
        date_filter_layout = QVBoxLayout()
        date_label = QLabel("Filtrar por fecha:")
        self.honeypotDateFilterBtn = QPushButton("Seleccionar fecha")
        self.honeypotDateFilterBtn.clicked.connect(self._show_honeypot_date_picker)
        self.honeypotSelectedDate = None
        date_filter_layout.addWidget(date_label)
        date_filter_layout.addWidget(self.honeypotDateFilterBtn)
        control_layout.addLayout(date_filter_layout)
        
        # Selector de base de datos (derecha)
        db_selector_layout = QVBoxLayout()
        self.db_label = QLabel("Base de datos: No seleccionada")
        db_selector_layout.addWidget(self.db_label)
        
        # Botón de selección
        self.selectHoneypotButton = QPushButton("Seleccionar base de datos")
        self.selectHoneypotButton.clicked.connect(self._select_honeypot_db)
        db_selector_layout.addWidget(self.selectHoneypotButton)
        
        control_layout.addLayout(db_selector_layout)
        
        layout.addWidget(control_frame)
        
        # Tabla de registros
        self.honeypot_table = QTableWidget()
        self.honeypot_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)  # Solo lectura
        layout.addWidget(self.honeypot_table)
        
        # Añadir la pestaña
        self.tabWidget.addTab(honeypot_tab, "Registros honeypot")

    def show_date_picker(self):
        try:
            # Obtener fechas disponibles
            available_dates = RecordManager.get_available_dates()  # Cambia esto al método correcto de tu RecordManager
            
            # Crear el diálogo
            dialog = DatePickerDialog(available_dates, self)
            self._configure_dialog(dialog)
            dialog.date_selected.connect(self.on_date_selected)
            
            # Calcular la posición para el diálogo
            button_pos = self.dateFilterBtn.mapToGlobal(self.dateFilterBtn.rect().bottomLeft())
            dialog.move(button_pos)
            
            # Mostrar el diálogo
            dialog.exec_()
        except Exception as e:
            self._show_error("Error", f"Error al cargar fechas: {str(e)}")

    def on_date_selected(self, date):
        self.selectedDate = date if date else None
        # Actualizar el texto del botón
        if self.selectedDate:
            self.dateFilterBtn.setText(f"Fecha: {self.selectedDate}")
        else:
            self.dateFilterBtn.setText("Todas las fechas")
        # Actualizar la búsqueda
        self.search_records()

    def update_theme_button(self):
        """Actualiza el icono y tooltip del botón según el tema actual"""
        if self.current_theme == "light":
            icon_path = os.path.join(self.icons_path, "sun.svg")
            tooltip = "Cambiar a tema oscuro"
        else:
            icon_path = os.path.join(self.icons_path, "moon.svg")
            tooltip = "Cambiar a tema claro"

        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
            self.theme_button.setIcon(icon)
            self.theme_button.setToolTip(tooltip)

    def toggle_theme(self):
        """Alterna entre tema claro y oscuro"""
        if self.current_theme == "light":
            self.current_theme = "dark"
            self.setStyleSheet(DARK_THEME)
        else:
            self.current_theme = "light"
            self.setStyleSheet(LIGHT_THEME)
        
        self.update_theme_button()

        # Actualizar el tema en las ventanas de detalles abiertas
        for window in self.detailWindows:
            if not window.isHidden():
                window.apply_theme(self.current_theme)

    def update_nmap_command(self):
        target = self.targetInput.text().strip() or DEFAULT_TARGET
        scan_type = "UDP" if self.scanTypeCombo.currentText() == "UDP" else "TCP"
        
        # Base de opciones para el escaneo
        base_options = "-T5 --script vulners"
        
        # Opciones específicas según el tipo de escaneo
        if scan_type == "UDP":
            options = f"-sUV -O {base_options}"  # UDP scan with version detection
        else:
            options = f"-sV -O {base_options}"   # TCP scan with version detection
            
        # Actualizar el texto del comando
        command = f"nmap {options} {target}"
        self.previewLabel.setText(command)

    def begin_scan(self):
        # Deshabilitar botón durante el escaneo
        self.scanButton.setEnabled(False)
        self.scanButton.setText("Escaneando...")
        QApplication.processEvents()  # Actualizar la interfaz

        try:
            target = self.targetInput.text().strip() or DEFAULT_TARGET
            scan_type = "UDP" if self.scanTypeCombo.currentText() == "UDP" else "TCP"

            # Realizar el escaneo
            scanner = NmapScanner()
            scan_results = scanner.scan_target(
                target, 
                scan_type,
                lambda msg: self.resultArea.append(msg)
            )

            if scan_results:
                # Procesar resultados
                processor = ScanResultProcessor(
                    scan_results,
                    lambda msg: self.resultArea.append(msg)
                )
                processor.process_results()

        except Exception as e:
            self.resultArea.append(f"❌ Error durante el escaneo: {e}")
        finally:
            # Restaurar el botón
            self.scanButton.setEnabled(True)
            self.scanButton.setText("Iniciar escaneo")

    def refresh_records(self):
        """Limpia los filtros y actualiza la lista de registros"""
        # Resetear filtro de fecha
        self.selectedDate = None
        self.dateFilterBtn.setText("Seleccionar fecha")
        
        # Limpiar filtro de IP
        self.ipFilter.clear()
        
        # Actualizar registros
        self.search_records()

    def search_records(self):
        try:
            # Limpiar tabla actual
            self.recordsTable.setRowCount(0)

            # Obtener filtros
            date_filter = self.selectedDate if self.selectedDate else None
            ip_filter = self.ipFilter.text().strip()

            # Buscar registros
            record_manager = RecordManager()
            records = record_manager.search_records(date_filter, ip_filter)

            # Llenar tabla con resultados
            for record in records:
                row = self.recordsTable.rowCount()
                self.recordsTable.insertRow(row)
                
                # Deshabilitar ordenamiento mientras se agregan items
                self.recordsTable.setSortingEnabled(False)
                
                # Añadir datos
                # Fecha (ordenable por fecha/hora)
                fecha_item = QTableWidgetItem(record["fecha"])
                fecha_item.setData(Qt.ItemDataRole.UserRole, record["fecha"])  # Para ordenamiento correcto
                self.recordsTable.setItem(row, 0, fecha_item)
                
                # IP (ordenable por octetos)
                ip_item = QTableWidgetItem(record["ip_host"])
                # Convertir IP a número para ordenamiento correcto
                ip_value = sum(int(x) * (256 ** (3-i)) for i, x in enumerate(record["ip_host"].split('.')))
                ip_item.setData(Qt.ItemDataRole.UserRole, ip_value)
                self.recordsTable.setItem(row, 1, ip_item)
                
                # Puertos (ordenable numéricamente)
                puertos_item = QTableWidgetItem()
                puertos_item.setData(Qt.ItemDataRole.DisplayRole, str(record["puertos_abiertos"]))
                puertos_item.setData(Qt.ItemDataRole.UserRole, int(record["puertos_abiertos"]))
                self.recordsTable.setItem(row, 2, puertos_item)
                
                # Vulnerabilidades (ordenable numéricamente)
                vulns_item = QTableWidgetItem()
                vulns_item.setData(Qt.ItemDataRole.DisplayRole, str(record["vulnerabilidades"]))
                vulns_item.setData(Qt.ItemDataRole.UserRole, int(record["vulnerabilidades"]))
                self.recordsTable.setItem(row, 3, vulns_item)
                
                # Reactivar ordenamiento
                self.recordsTable.setSortingEnabled(True)
                
                # Botón de detalles
                details_button = QPushButton("Ver más detalles")
                details_button.setFixedHeight(27)
                details_button.setStyleSheet("""
                    QPushButton {
                        padding: 2px 8px;  /* padding vertical: 2px, horizontal: 8px */
                    }
                """)
                details_button.clicked.connect(
                    lambda checked, r=record: self.show_scan_details(r["id"], r["ip_host"])
                )
                self.recordsTable.setCellWidget(row, 4, details_button)

        except Exception as e:
            self._show_error("Error", f"Error al buscar registros: {str(e)}")

    def on_table_sort(self, logical_index, order):
        """Maneja el evento de ordenamiento de la tabla"""
        # Guardar el estado de ordenamiento actual
        self.recordsTable.horizontalHeader().setSortIndicator(logical_index, order)

    def show_scan_details(self, scan_id: int, host_ip: str):
        try:
            # Limpiar las ventanas cerradas de la lista
            self.detailWindows = [w for w in self.detailWindows if not w.isHidden()]
            
            # Obtener detalles del escaneo
            record_manager = RecordManager()
            scan_details = record_manager.get_scan_details(scan_id, host_ip)
            
            # Crear diálogo como ventana independiente
            dialog = ScanDetailsDialog(scan_details, self)  # Pasamos self como parent para heredar el tema
            dialog.setWindowTitle(f"Detalles del escaneo - {host_ip}")
            
            # Configurar como ventana independiente
            dialog.setWindowFlags(
                Qt.WindowType.Window |  # Hacer que sea una ventana independiente
                Qt.WindowType.WindowMinMaxButtonsHint |  # Permitir minimizar/maximizar
                Qt.WindowType.WindowCloseButtonHint |  # Agregar botón de cerrar
                Qt.WindowType.WindowSystemMenuHint  # Agregar menú de sistema
            )
            
            # Establecer tamaño inicial y heredar icono de la aplicación principal
            dialog.setGeometry(100, 100, 800, 600)
            dialog.setWindowIcon(self.windowIcon())
            
            # Aplicar el tema actual
            dialog.apply_theme(self.current_theme)
            
            # Conectar la señal destroyed para limpieza automática
            dialog.destroyed.connect(lambda: self.detailWindows.remove(dialog) 
                                  if dialog in self.detailWindows else None)
            
            # Agregar a la lista de ventanas activas
            self.detailWindows.append(dialog)
            
            # Mostrar diálogo de forma no modal
            dialog.show()  # Usar show() en lugar de exec_() para no bloquear
            
        except Exception as e:
            self._show_error("Error", f"Error al mostrar detalles: {str(e)}")

    def open_remote_config(self):
        try:
            # Crear diálogo de configuración remota
            dialog = RemoteConfigDialog(self)
            dialog.setWindowTitle("Configuración Remota")
            dialog.setWindowIcon(self.windowIcon())
            dialog.apply_theme(self.current_theme)
            
            # Mostrar diálogo de forma modal
            dialog.exec_()
        except Exception as e:
            self._show_error("Error", f"Error al abrir configuración remota: {str(e)}")

    def show_remote_config(self):
        """Muestra el diálogo de configuración/estado de conexión remota"""
        # Verificar si ya hay una conexión activa intentando usar el SFTP
        try:
            if self.remote_manager.sftp:
                try:
                    # Intentar una operación simple para verificar la conexión
                    self.remote_manager.sftp.stat('.')
                    # Si llegamos aquí, la conexión está activa
                    dialog = RemoteStatusDialog(self.remote_manager, self)
                    self._configure_dialog(dialog)
                    dialog.exec_()
                    return
                except Exception:
                    # La conexión está rota, limpiarla
                    self.remote_manager.close_connections()
            
            # No hay conexión o se perdió, mostrar diálogo de configuración
            dialog = RemoteConfigDialog(self)
            dialog.set_remote_manager(self.remote_manager)
            self._configure_dialog(dialog)
            dialog.exec_()
            
        except Exception as e:
            # Si hay cualquier error inesperado
            self._show_error("Error", f"Error al verificar la conexión: {str(e)}")
            self.remote_manager.close_connections()

    def _select_honeypot_db(self):
        """Abre el diálogo para seleccionar una base de datos remota del honeypot"""
        try:
            if not self.remote_manager.is_connected():
                self._show_warning(
                    "Conexión remota requerida",
                    "Debe establecer una conexión remota primero para acceder a las bases de datos"
                )
                return
            
            dialog = RemoteFileSelector(self.remote_manager, self)
            dialog.file_selected.connect(self._load_honeypot_db)
            
            # Mostrar el diálogo
            dialog.exec_()

        except Exception as e:
            self._show_error(
                "Error",
                f"Error al abrir el selector de archivos: {str(e)}"
            )

    def _load_honeypot_db(self, remote_path):
        """Carga una base de datos del honeypot desde la ruta remota especificada"""
        try:
            # Crear directorio temporal si no existe
            temp_dir = os.path.join(tempfile.gettempdir(), "picir_honeypot")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Verificar que sea un archivo SQLite válido y tenga el nombre correcto
            filename = os.path.basename(remote_path)
            name_without_ext = os.path.splitext(filename)[0].lower()
            
            if not self._is_sqlite_file(filename):
                raise Exception("El archivo seleccionado no es una base de datos SQLite válida")
                
            if name_without_ext != "dionaea":
                raise Exception("La base de datos seleccionada no es una base de datos válida del honeypot")
            
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
            
            # Verificar que exista la tabla connections
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='connections';")
            if not cursor.fetchone():
                raise Exception("El archivo seleccionado no es una base de datos válida del honeypot")
            
            # Consulta para obtener los datos ordenados por fecha descendente
            query = """
                SELECT 
                    connection_timestamp,
                    connection_transport,
                    local_port,
                    connection_protocol,
                    local_host,
                    remote_host,
                    remote_hostname,
                    remote_port
                FROM connections
                ORDER BY connection_timestamp DESC;
            """
            
            cursor.execute(query)
            records = cursor.fetchall()
            
            # Definir las columnas que queremos mostrar
            columns = [
                "Fecha y hora", "Protocolo", "Puerto", "Servicio", 
                "IP local", "IP remoto", "Nombre remoto", "Puerto remoto"
            ]
            
            # Configurar la tabla
            self.honeypot_table.setColumnCount(len(columns))
            self.honeypot_table.setHorizontalHeaderLabels(columns)
            
            # Ajustar tamaño y comportamiento de las columnas
            header = self.honeypot_table.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            
            # Establecer anchos iniciales para las columnas
            column_widths = {
                0: 180,  # Fecha y Hora
                1: 100,  # Protocolo (TCP/UDP)
                2: 100,  # Puerto local
                3: 100,  # Servicio (SMB/RDP)
                5: 120,  # IP local
                6: 120,  # IP remoto
                7: 150,  # Nombre remoto
                8: 100,  # Puerto remoto
            }
            
            for col, width in column_widths.items():
                self.honeypot_table.setColumnWidth(col, width)
            
            # Permitir ordenamiento
            self.honeypot_table.setSortingEnabled(True)
            header.setSortIndicatorShown(True)
            
            # Eliminar filas vacías
            for row in range(self.honeypot_table.rowCount() - 1, -1, -1):
                is_empty = True
                for col in range(self.honeypot_table.columnCount()):
                    item = self.honeypot_table.item(row, col)
                    if item and item.text().strip():
                        is_empty = False
                        break
                if is_empty:
                    self.honeypot_table.removeRow(row)
            
            # Procesar y mostrar los datos
            self.honeypot_table.setRowCount(len(records))
            
            for row, record in enumerate(records):
                # Convertir timestamp Unix a fecha legible
                timestamp = datetime.fromtimestamp(record[0]).strftime('%Y-%m-%d %H:%M:%S')
                
                # Convertir protocolo de transporte a mayúsculas
                transport = record[1].upper() if record[1] else "Desconocido"
                
                # Puerto local
                local_port = str(record[2]) if record[2] is not None else "Desconocido"
                
                # Convertir protocolo de conexión
                protocol = {
                    'smbd': 'SMB',
                    'Blackhole': 'RDP'
                }.get(record[3], record[3] or "Desconocido")
                
                # Host local
                local_host = record[4] or "Desconocido"
                
                # Host remoto
                remote_host = record[5] or "Desconocido"
                
                # Nombre de host remoto
                remote_hostname = record[6] or "Desconocido"
                
                # Puerto remoto
                remote_port = str(record[7]) if record[7] is not None else "Desconocido"
                
                # Añadir datos a la tabla
                self.honeypot_table.setItem(row, 0, QTableWidgetItem(timestamp))
                self.honeypot_table.setItem(row, 1, QTableWidgetItem(transport))
                self.honeypot_table.setItem(row, 2, QTableWidgetItem(local_port))
                self.honeypot_table.setItem(row, 3, QTableWidgetItem(protocol))
                self.honeypot_table.setItem(row, 4, QTableWidgetItem(local_host))
                self.honeypot_table.setItem(row, 5, QTableWidgetItem(remote_host))
                self.honeypot_table.setItem(row, 6, QTableWidgetItem(remote_hostname))
                self.honeypot_table.setItem(row, 7, QTableWidgetItem(remote_port))
            
            # Ajustar tamaño de columnas
            self.honeypot_table.resizeColumnsToContents()
            
            # Actualizar etiqueta con el estado de la base de datos
            self.db_label.setText("Base de datos: Seleccionada y cargada")
            
            # Limpiar recursos
            cursor.close()
            conn.close()
            
            # Eliminar archivo temporal
            os.remove(local_path)
            
            # Aplicar filtros actuales
            self._apply_honeypot_filters()
            
            # Mostrar mensaje de éxito
            self._show_message(
                "Éxito",
                "Base de datos del honeypot cargada exitosamente",
                QMessageBox.Icon.Information
            )
            
        except Exception as e:
            self._show_error(
                "Error",
                f"Error al cargar la base de datos del honeypot: {str(e)}"
            )

    def _is_sqlite_file(self, filename):
        """Verifica si un nombre de archivo tiene una extensión válida de SQLite"""
        return filename.lower().endswith(('.db', '.sqlite', '.db3', '.sqlite3'))

    def _refresh_honeypot(self):
        """Recarga los datos del honeypot desde la base de datos actual."""
        try:
            current_db = self.db_label.text()
            if "No hay base de datos seleccionada" in current_db:
                self._show_warning(
                    "Advertencia",
                    "Primero debe seleccionar una base de datos del honeypot"
                )
                return
                
            # Resetear el filtro de fecha
            self.honeypotSelectedDate = None
            self.honeypotDateFilterBtn.setText("Seleccionar fecha")
            
            # Recargar la base de datos actual
            remote_path = current_db.replace("Base de datos: ", "")
            self._load_honeypot_db(remote_path)
            
        except Exception as e:
            self._show_error(
                "Error",
                f"Error al recargar los datos del honeypot: {str(e)}"
            )

    def _show_honeypot_date_picker(self):
        """Muestra el selector de fecha para filtrar los registros del honeypot."""
        try:
            if not self.honeypot_table.rowCount():
                self._show_warning(
                    "Advertencia",
                    "No hay datos para filtrar"
                )
                return
                
            # Obtener fechas únicas de la tabla
            unique_dates = set()
            for row in range(self.honeypot_table.rowCount()):
                item = self.honeypot_table.item(row, 0)
                if item is not None and item.text():
                    date_str = item.text().split()[0]  # Solo la fecha, sin hora
                    unique_dates.add(date_str)
            
            # Ordenar fechas
            available_dates = sorted(list(unique_dates), reverse=True)
            
            # Crear diálogo
            dialog = DatePickerDialog(available_dates, self)
            self._configure_dialog(dialog)
            dialog.date_selected.connect(self._on_honeypot_date_selected)
            
            # Calcular posición para el diálogo
            button_pos = self.honeypotDateFilterBtn.mapToGlobal(self.honeypotDateFilterBtn.rect().bottomLeft())
            dialog.move(button_pos)
            
            # Mostrar diálogo
            dialog.exec_()
            
        except Exception as e:
            self._show_error(
                "Error",
                f"Error al mostrar el selector de fecha: {str(e)}"
            )

    def _on_honeypot_date_selected(self, date):
        """Maneja la selección de fecha para el filtro del honeypot.
        
        Args:
            date (str): Fecha seleccionada en formato YYYY-MM-DD o cadena vacía para mostrar todo
        """
        self.honeypotSelectedDate = date
        
        # Actualizar texto del botón
        if date:
            self.honeypotDateFilterBtn.setText(f"Fecha: {date}")
        else:
            self.honeypotDateFilterBtn.setText("Todas las fechas")
        
        # Aplicar filtro
        self._apply_honeypot_filters()

    def _show_message(self, title: str, message: str, icon: QMessageBox.Icon = QMessageBox.Icon.Information):
        """Muestra un mensaje.
        
        Args:
            title (str): Título del mensaje
            message (str): Contenido del mensaje
            icon (QMessageBox.Icon): Icono a mostrar (Information, Warning, Critical)
        """
        # Hacemos el mensaje corto más ancho añadiendo espacios a los lados
        padded_message = message.center(50)  # Centrar en 50 caracteres con espacios
        
        msg_box = QMessageBox(self)
        msg_box.setIcon(icon)
        msg_box.setWindowTitle(title)
        msg_box.setText(f"{padded_message}\n")
        msg_box.setMinimumWidth(400)
        
        # Configurar el diálogo con el tema actual
        self._configure_dialog(msg_box)
        
        # Asegurar que los botones estándar también reciben el estilo
        for button in msg_box.buttons():
            button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        
        msg_box.exec_()

    def _show_error(self, title: str, message: str):
        """Muestra un mensaje de error con formato correcto."""
        self._show_message(title, message, QMessageBox.Icon.Critical)

    def _show_warning(self, title: str, message: str):
        """Muestra un mensaje de advertencia con formato correcto."""
        self._show_message(title, message, QMessageBox.Icon.Warning)

    def _apply_honeypot_filters(self):
        """Aplica los filtros actuales a la tabla del honeypot."""
        try:
            # Mostrar/ocultar filas según el filtro de fecha
            for row in range(self.honeypot_table.rowCount()):
                date_item = self.honeypot_table.item(row, 0)
                if date_item:
                    should_show = True
                    if self.honeypotSelectedDate:
                        row_date = date_item.text().split()[0]  # Solo la fecha, sin hora
                        should_show = row_date == self.honeypotSelectedDate
                    
                    self.honeypot_table.setRowHidden(row, not should_show)
                    
        except Exception as e:
            self._show_error(
                "Error",
                f"Error al aplicar filtros: {str(e)}"
            )

    def _configure_dialog(self, dialog):
        """Configura un diálogo con el tema e icono actuales.
        
        Args:
            dialog: El diálogo a configurar
        """
        # Establecer el icono de la aplicación
        dialog.setWindowIcon(self.windowIcon())
        
        # Colores base según el tema
        is_dark = self.current_theme == "dark"
        bg_color = "#2b2b2b" if is_dark else "#f0f0f0"
        text_color = "#ffffff" if is_dark else "#000000"
        
        # Crear paleta de colores para el tema
        palette = QPalette()
        bg = QColor(bg_color)
        fg = QColor(text_color)
        palette.setColor(QPalette.ColorRole.Window, bg)
        palette.setColor(QPalette.ColorRole.WindowText, fg)
        palette.setColor(QPalette.ColorRole.Base, QColor("#363636" if is_dark else "#ffffff"))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#424242" if is_dark else "#f7f7f7"))
        palette.setColor(QPalette.ColorRole.Text, fg)
        palette.setColor(QPalette.ColorRole.Button, bg)
        palette.setColor(QPalette.ColorRole.ButtonText, fg)
        palette.setColor(QPalette.ColorRole.Highlight, QColor("#0d47a1" if is_dark else "#308cc6"))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))

        # Estilos específicos para cada tipo de widget
        widget_styles = {
            QPushButton: f"""
                QPushButton {{
                    background-color: {bg_color};
                    color: {text_color};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                    border-radius: 4px;
                    padding: 6px 12px;
                    min-width: 80px;
                }}
                QPushButton:hover {{
                    background-color: {'#404040' if is_dark else '#e0e0e0'};
                }}
                QPushButton:pressed {{
                    background-color: {'#303030' if is_dark else '#d0d0d0'};
                }}
            """,
            QLineEdit: f"""
                QLineEdit {{
                    background-color: {'#363636' if is_dark else '#ffffff'};
                    color: {text_color};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                    border-radius: 4px;
                    padding: 4px;
                }}
            """,
            QTextEdit: f"""
                QTextEdit {{
                    background-color: {'#363636' if is_dark else '#ffffff'};
                    color: {text_color};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                    border-radius: 4px;
                    padding: 4px;
                }}
            """,
            QComboBox: f"""
                QComboBox {{
                    background-color: {'#363636' if is_dark else '#ffffff'};
                    color: {text_color};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                    border-radius: 4px;
                    padding: 4px;
                }}
                QComboBox::drop-down {{
                    border: none;
                }}
                QComboBox::down-arrow {{
                    image: url({'down_arrow_white.png' if is_dark else 'down_arrow_black.png'});
                    width: 12px;
                    height: 12px;
                }}
            """,
            QTableWidget: f"""
                QTableWidget {{
                    background-color: {'#363636' if is_dark else '#ffffff'};
                    color: {text_color};
                    gridline-color: {'#404040' if is_dark else '#d0d0d0'};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                }}
                QHeaderView::section {{
                    background-color: {bg_color};
                    color: {text_color};
                    padding: 4px;
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                }}
            """,
            QTreeWidget: f"""
                QTreeWidget {{
                    background-color: {'#363636' if is_dark else '#ffffff'};
                    color: {text_color};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                }}
                QTreeWidget::item:hover {{
                    background-color: {'#404040' if is_dark else '#e0e0e0'};
                }}
            """,
            QLabel: f"color: {text_color}; background-color: transparent;",
            QTabBar: f"""
                QTabBar::tab {{
                    background-color: {bg_color};
                    color: {text_color};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                    padding: 8px 12px;
                    margin-right: 2px;
                }}
                QTabBar::tab:selected {{
                    background-color: {'#404040' if is_dark else '#e0e0e0'};
                }}
            """,
            QSpinBox: f"""
                QSpinBox {{
                    background-color: {'#363636' if is_dark else '#ffffff'};
                    color: {text_color};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                    border-radius: 4px;
                    padding: 4px;
                }}
            """,
            QDateEdit: f"""
                QDateEdit {{
                    background-color: {'#363636' if is_dark else '#ffffff'};
                    color: {text_color};
                    border: 1px solid {'#404040' if is_dark else '#c0c0c0'};
                    border-radius: 4px;
                    padding: 4px;
                }}
            """
        }

        # Si el diálogo tiene un método específico para aplicar el tema, usarlo primero
        if hasattr(dialog, 'apply_theme'):
            dialog.apply_theme(self.current_theme)

        # Aplicar paleta al diálogo
        dialog.setPalette(palette)

        # Estilo base para el diálogo
        dialog_style = f"""
            QDialog, QMessageBox {{
                background-color: {bg_color};
                color: {text_color};
            }}
        """
        dialog.setStyleSheet(dialog_style)

        # Aplicar estilos específicos a los widgets hijos
        for widget in dialog.findChildren(QWidget):
            # Aplicar paleta a todos los widgets
            widget.setPalette(palette)
            
            # Aplicar estilos específicos según el tipo de widget
            for widget_class, style in widget_styles.items():
                if isinstance(widget, widget_class):
                    widget.setStyleSheet(style)
                    break  # Una vez aplicado el estilo, pasar al siguiente widget
                    
            # Asegurarse de que los botones tengan el cursor correcto
            if isinstance(widget, QPushButton):
                widget.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
                
        # Forzar actualización visual
        dialog.update()
