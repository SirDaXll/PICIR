import sys
import sqlite3
import nmap
from datetime import datetime
from collections import Counter
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QLineEdit, QTextEdit

# Constantes
DB_NAME = "data/hosts_puertos.db"
DEFAULT_TARGET = "scanme.nmap.org"

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Escáner Nmap - PICIR")
        self.setGeometry(100, 100, 600, 400)

        # Layout principal
        layout = QVBoxLayout()

        # Campo para ingresar el target
        self.targetInput = QLineEdit(self)
        self.targetInput.setPlaceholderText("Ingrese la IP o nombre del host (Deje vacío para usar scanme.nmap.org)")
        layout.addWidget(self.targetInput)

        # Botón para iniciar el escaneo
        self.scanButton = QPushButton("Iniciar escaneo", self)
        self.scanButton.clicked.connect(self.beginScan)
        layout.addWidget(self.scanButton)

        # Área para mostrar resultados
        self.resultArea = QTextEdit(self)
        self.resultArea.setReadOnly(True)
        layout.addWidget(self.resultArea)

        # Contenedor principal
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    # Inicia el escaneo y procesa los resultados
    def beginScan(self):
        target = self.targetInput.text().strip() or DEFAULT_TARGET
        #options = "-sS -sV -O -A -p 1-1000"
        self.resultArea.append(f"Iniciando escaneo para: {target}")

        try:
            scanner = nmap.PortScanner()
            scanner.scan(target)

            if not scanner.all_hosts():
                self.resultArea.append("No se encontraron hosts en el escaneo.")
                return

            timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
            portState = Counter()

            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                for host in scanner.all_hosts():
                    self.procesar_host(scanner, host, cursor, timestamp, portState)

            self.summary(portState)
            self.resultArea.append("\n✅ Datos guardados en la base de datos.")

        except nmap.PortScannerError as e:
            self.resultArea.append(f"❌ Error al inicializar el escáner: {e}")
        except sqlite3.Error as e:
            self.resultArea.append(f"❌ Error al interactuar con la base de datos: {e}")
        except Exception as e:
            self.resultArea.append(f"❌ Error inesperado: {e}")

    # Procesa un host escaneado y guarda los datos en la base de datos
    def procesar_host(self, scanner, host, cursor, timestamp, portState):
        self.resultArea.append(f"\nResultados para: {host}")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port].get('name', 'desconocido')
                version = scanner[host][proto][port].get('version', '')

                # Mostrar resultados
                self.resultArea.append(f"  - [{proto.upper()}] Puerto {port}: {state}, Servicio: {service}, Versión: {version or 'desconocida'}")

                # Guardar en la base de datos
                self.dbSave(cursor, timestamp, host, proto.upper(), port, state, service, version)

                # Contar el state del puerto
                portState[state] += 1

    # Guarda un registro en la base de datos
    # Agregar el campo 'CVE' en caso de que se detecte una vulnerabilidad
    # Agregar un campo con la 'descripcion' de la vulnerabilidad
    def dbSave(self, cursor, timestamp, host, protocol, port, state, service, version):
        cursor.execute("""
            INSERT INTO hosts_puertos (fecha_hora, host, protocolo, puerto, estado, servicio, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, host, protocol, port, state, service, version))

    # Muestra un resumen del escaneo
    def summary(self, portState):
        resumen = "\nResumen del escaneo:\n"
        for state, quantity in portState.items():
            resumen += f"  - {state}: {quantity} puertos\n"
        total = sum(portState.values())
        resumen += f"Total de puertos escaneados: {total}"
        self.resultArea.append(resumen)

# Ejecuta la aplicación
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
