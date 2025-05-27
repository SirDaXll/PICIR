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
                self.resultArea.append("❌ No se encontraron hosts en el escaneo.\n")
                return

            timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
            portState = Counter()

            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                for host in scanner.all_hosts():
                    # Obtener sistema operativo
                    if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                        osInfo = scanner[host]['osmatch'][0]
                        osName = osInfo.get('name', 'Desconocido')
                    else:
                        osName = None

                    # Insertar en escaneos y obtener escaneo_id
                    cursor.execute("""
                        INSERT INTO escaneos (fecha_hora, host, comando, sistema_operativo)
                        VALUES (?, ?, ?, ?)
                    """, (timestamp, host, options, osName))
                    escaneoId = cursor.lastrowid

                    self.procesarHost(scanner, host, cursor, escaneoId, portState)

                conn.commit()

            self.summary(portState)
            self.resultArea.append("✅ Datos guardados en la base de datos.")

        except nmap.PortScannerError as e:
            self.resultArea.append(f"❌ Error al inicializar el escáner: {e}")
        except sqlite3.Error as e:
            self.resultArea.append(f"❌ Error al interactuar con la base de datos: {e}")
        except Exception as e:
            self.resultArea.append(f"❌ Error inesperado: {e}")

    # Procesa un host escaneado y guarda los datos en la base de datos
    def procesarHost(self, scanner, host, cursor, escaneoId, portState):
        self.resultArea.append(f"\nResultados para: {host}")

        # Mostrar información del sistema operativo si está disponible
        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
            osInfo = scanner[host]['osmatch'][0]
            osName = osInfo.get('name', 'Desconocido')
            osAccuracy = osInfo.get('accuracy', '0')
            self.resultArea.append(f" ➤ Sistema operativo detectado: {osName} (Precisión: {osAccuracy}%)")
        else:
            self.resultArea.append(" ➤ Sistema operativo: No detectado.")

        # Espacio para mostrar resultados del script "vulners"
        vulnInfo = ""
        
        # Mostrar información avanzada (-A)
        #advanced_info = ""

        # Scripts NSE por puerto
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                portData = scanner[host][proto][port]
                state = portData['state']
                service = portData.get('name', 'desconocido')
                version = portData.get('version', '')

                # Mostrar resultados
                self.resultArea.append(f"  - [{proto.upper()}] Puerto {port}: {state}, Servicio: {service}, Versión: {version or 'desconocida'}")

                # Guardar puerto y obtener puerto_id
                cursor.execute("""
                    INSERT INTO puertos (escaneo_id, protocolo, puerto, estado, servicio, version)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (escaneoId, proto.upper(), port, state, service, version))
                puertoId = cursor.lastrowid


                # Guardar vulnerabilidades si existen
                if 'script' in portData and 'vulners' in portData['script']:
                    vulnOutput = portData['script']['vulners']
                    vulnInfo += f"\n[VULN] Puerto {port}:\n{vulnOutput}\n"
                    self.guardarVulnerabilidad(cursor, puertoId, vulnOutput)

                portState[state] += 1

        if vulnInfo:
            self.resultArea.append("\n[Resultados del script 'vulners']" + vulnInfo)

                # Mostrar scripts NSE si existen
                #if 'script' in portData:
                #    for script_name, script_output in portData['script'].items():
                #        advanced_info += f"    [NSE] {script_name}: {script_output}\n"

        # Traceroute si existe
        #if 'traceroute' in scanner[host]:
        #    advanced_info += "  ➤ Traceroute:\n"
        #    for hop in scanner[host]['traceroute']['hop']:
        #        advanced_info += f"    Hop {hop['ttl']}: {hop['ipaddr']} ({hop.get('rtt', 'N/A')} ms)\n"

        #if advanced_info:
        #    self.resultArea.append("\n[Información avanzada -A]\n" + advanced_info)

    # Procesa y guarda las vulnerabilidades extraídas del script 'vulners' en la base de datos
    def guardarVulnerabilidad(self, cursor, puertoId, vulnOutput):
        ignorarPrimeraLinea = True  # Indicador para ignorar la primera línea después del encabezado del puerto

        for line in vulnOutput.splitlines():
            # Ignorar la primera línea después del encabezado del puerto
            if ignorarPrimeraLinea:
                ignorarPrimeraLinea = False
                continue

            # Dividir la línea en partes
            parts = line.split()
            if len(parts) < 2:
                # Si la línea no tiene suficientes partes para ser una vulnerabilidad, ignorarla
                continue

            idVulnerabilidad = parts[0]  # El identificador puede ser CVE o cualquier otro
            cvss = None
            descripcion = ""
            explotable = "*EXPLOIT*" in line

            # Extraer el puntaje CVSS si está presente
            if parts[1].replace('.', '', 1).isdigit():
                cvss = float(parts[1])
                descripcion = " ".join(parts[2:]) if len(parts) > 2 else ""
            else:
                descripcion = " ".join(parts[1:]) if len(parts) > 1 else ""

            # Guardar la vulnerabilidad en la base de datos
            cursor.execute("""
                INSERT INTO vulnerabilidades (puerto_id, id_vulnerabilidad, explotable, cvss, descripcion)
                VALUES (?, ?, ?, ?, ?)
            """, (puertoId, idVulnerabilidad, explotable, cvss, descripcion))

    # Muestra un resumen del escaneo
    def summary(self, portState):
        resumen = "\nResumen del escaneo:\n"
        total_vulnerabilidades = 0
        total_explotables = 0

        for state, quantity in portState.items():
            resumen += f"  - {state}: {quantity} puertos\n"
        total = sum(portState.values())
        resumen += f"Total de puertos escaneados: {total}\n"

        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            # Obtener el ID del último escaneo (el escaneo actual)
            cursor.execute("SELECT MAX(id) FROM escaneos")
            escaneo_actual_id = cursor.fetchone()[0]

            # Obtener la cantidad de vulnerabilidades y explotables del escaneo actual
            cursor.execute("""
                SELECT COUNT(*), SUM(CASE WHEN explotable THEN 1 ELSE 0 END)
                FROM vulnerabilidades
                WHERE escaneo_id = ?
            """, (escaneo_actual_id,))
            total_vulnerabilidades, total_explotables = cursor.fetchone()
            total_vulnerabilidades = total_vulnerabilidades or 0
            total_explotables = total_explotables or 0

        resumen += f"Total de vulnerabilidades encontradas: {total_vulnerabilidades}\n"
        resumen += f"Total de vulnerabilidades explotables: {total_explotables}\n"

        self.resultArea.append(resumen)

# Ejecuta la aplicación
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
