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
        self.targetInput.setPlaceholderText("Ingrese la IP o nombre del host (Por defecto se utiliza scanme.nmap.org)")
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
        # Argumentos para el escaneo de servicios y su versión, detección de sistema operativo, escaneo en alta velocidad y el script para vulnerabilidades
        options = "-sV -O -T5 --script vulners"
        self.resultArea.append(f"Iniciando escaneo para: {target}")
        self.resultArea.append(f"Argumentos de Nmap: {options}")

        try:
            scanner = nmap.PortScanner()
            scanner.scan(target, arguments=options)

            if not scanner.all_hosts():
                self.resultArea.append("No se encontraron hosts en el escaneo.")
                return

            timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
            portState = Counter()

            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                for host in scanner.all_hosts():
                    # Obtener sistema operativo
                    if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                        os_info = scanner[host]['osmatch'][0]
                        os_name = os_info.get('name', 'Desconocido')
                    else:
                        os_name = None

                    # Insertar en escaneos y obtener escaneo_id
                    cursor.execute("""
                        INSERT INTO escaneos (fecha_hora, host, comando, sistema_operativo)
                        VALUES (?, ?, ?, ?)
                    """, (timestamp, host, options, os_name))
                    escaneo_id = cursor.lastrowid

                    self.procesar_host(scanner, host, cursor, escaneo_id, portState)

                conn.commit()

            self.summary(portState)
            self.resultArea.append("\n✅ Datos guardados en la base de datos.")

        except nmap.PortScannerError as e:
            self.resultArea.append(f"❌ Error al inicializar el escáner: {e}")
        except sqlite3.Error as e:
            self.resultArea.append(f"❌ Error al interactuar con la base de datos: {e}")
        except Exception as e:
            self.resultArea.append(f"❌ Error inesperado: {e}")

    # Procesa un host escaneado y guarda los datos en la base de datos
    def procesar_host(self, scanner, host, cursor, escaneo_id, portState):
        self.resultArea.append(f"\nResultados para: {host}")

        # Mostrar información del sistema operativo si está disponible
        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
            os_info = scanner[host]['osmatch'][0]
            os_name = os_info.get('name', 'Desconocido')
            os_accuracy = os_info.get('accuracy', '0')
            self.resultArea.append(f" ➤ Sistema operativo detectado: {os_name} (Precisión: {os_accuracy}%)")
        else:
            self.resultArea.append(" ➤ Sistema operativo: No detectado.")

        # Espacio para mostrar resultados del script "vulners"
        vuln_info = ""
        
        # Mostrar información avanzada (-A)
        #advanced_info = ""

        # Scripts NSE por puerto
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                port_data = scanner[host][proto][port]
                state = port_data['state']
                service = port_data.get('name', 'desconocido')
                version = port_data.get('version', '')

                # Mostrar resultados
                self.resultArea.append(f"  - [{proto.upper()}] Puerto {port}: {state}, Servicio: {service}, Versión: {version or 'desconocida'}")

                # Guardar puerto y obtener puerto_id
                cursor.execute("""
                    INSERT INTO puertos (escaneo_id, protocolo, puerto, estado, servicio, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (escaneo_id, proto.upper(), port, state, service, version))
                puerto_id = cursor.lastrowid

                # Guardar vulnerabilidades si existen
                if 'script' in port_data and 'vulners' in port_data['script']:
                    vuln_output = port_data['script']['vulners']
                    vuln_info += f"\n[VULN] Puerto {port}:\n{vuln_output}\n"
                    # Extraer CVEs del output (simplemente busca líneas que empiecen con CVE-)
                    for line in vuln_output.splitlines():
                        if line.startswith("CVE-"):
                            parts = line.split()
                            cve = parts[0]
                            descripcion = " ".join(parts[1:]) if len(parts) > 1 else ""
                            cursor.execute("""
                                INSERT INTO vulnerabilidades (puerto_id, cve, explotable, descripcion)
                                VALUES (?, ?, ?, ?)
                            """, (puerto_id, cve, None, descripcion))

                portState[state] += 1

        if vuln_info:
            self.resultArea.append("\n[Resultados del script 'vulners']" + vuln_info)

                # Mostrar scripts NSE si existen
                #if 'script' in port_data:
                #    for script_name, script_output in port_data['script'].items():
                #        advanced_info += f"    [NSE] {script_name}: {script_output}\n"

        # Traceroute si existe
        #if 'traceroute' in scanner[host]:
        #    advanced_info += "  ➤ Traceroute:\n"
        #    for hop in scanner[host]['traceroute']['hop']:
        #        advanced_info += f"    Hop {hop['ttl']}: {hop['ipaddr']} ({hop.get('rtt', 'N/A')} ms)\n"

        #if advanced_info:
        #    self.resultArea.append("\n[Información avanzada -A]\n" + advanced_info)

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
