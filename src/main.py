import sys
import sqlite3
import nmap
from datetime import datetime
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QLineEdit, QTextEdit

# Constantes
DB_NAME = "data/scans.db"
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
        options = "-sV -O -T5 --script vulners --system-dns"
        startTime = datetime.now()
        self.resultArea.append(f"Iniciando escaneo para: {target}")
        self.resultArea.append(f"Argumentos de Nmap: {options}")

        try:
            scanner = nmap.PortScanner()
            scanner.scan(target, arguments=options)

            if not scanner.all_hosts():
                self.resultArea.append("❌ No se encontraron hosts en el escaneo.\n")
                return
            
            endTime = datetime.now()
            tiempoRespuesta = (endTime - startTime).total_seconds()

            # Inicializar diccionario para contar estados de puertos
            portStates = {"abierto": 0, "filtrado": 0}

            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()

                # Insertar en escaneos
                cursor.execute("""
                    INSERT INTO escaneos (fecha_hora, comando, tiempo_respuesta)
                    VALUES (?, ?, ?)
                """, (startTime.isoformat(sep=' ', timespec='seconds'), options, tiempoRespuesta))
                idEscaneo = cursor.lastrowid

                for host in scanner.all_hosts():
                    self.procesarHost(scanner, host, cursor, idEscaneo, portStates)

                conn.commit()

            self.resultArea.append("✅ Datos guardados en la base de datos.")
            self.summary(portStates)

        except nmap.PortScannerError as e:
            self.resultArea.append(f"❌ Error al inicializar el escáner: {e}")
        except sqlite3.Error as e:
            self.resultArea.append(f"❌ Error al interactuar con la base de datos: {e}")
        except Exception as e:
            self.resultArea.append(f"❌ Error inesperado: {e}")

    # Procesa un host escaneado y guarda los datos en la base de datos
    def procesarHost(self, scanner, host, cursor, idEscaneo, portStates):
        self.resultArea.append(f"\nResultados para: {host}")

        # Conseguir SO del host
        osName = None
        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
            osInfo = scanner[host]['osmatch'][0]
            osName = osInfo.get('name', 'Desconocido')
            osAccuracy = osInfo.get('accuracy', '0')
            self.resultArea.append(f" ➤ Sistema operativo detectado: {osName} (Precisión: {osAccuracy}%)")
        else:
            self.resultArea.append(" ➤ Sistema operativo: No detectado.")

        # Conseguir dirección MAC del host
        macAddress = None
        if 'addresses' in scanner[host] and 'mac' in scanner[host]['addresses']:
            macAddress = scanner[host]['addresses']['mac']
            self.resultArea.append(f" ➤ Dirección MAC: {macAddress}")
        
        # Insertar información del host
        cursor.execute("""
            INSERT INTO escaneos_host (id_escaneo, id_host, direccion_mac, sistema_operativo)
            VALUES (?, ?, ?, ?)
        """, (idEscaneo, host, macAddress, osName))

        # Espacio para mostrar resultados del script "vulners"
        vulnInfo = ""

        # Script para escanear puertos y vulnerabilidades
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                portData = scanner[host][proto][port]
                state = portData['state']
                service = portData.get('name', 'desconocido')
                version = portData.get('version', '')

                # Actualizar conteo de puertos
                stateEsp = "abierto" if state == "open" else "filtrado"
                if stateEsp in portStates:
                    portStates[stateEsp] += 1

                # Mostrar resultados
                self.resultArea.append(f"  - [{proto.upper()}] Puerto {port}: {state}, Servicio: {service}, Versión: {version or 'desconocida'}")

                # Guardar información del puerto
                cursor.execute("""
                    INSERT INTO escaneos_puertos (id_escaneo, id_host, puerto, protocolo, estado, servicio, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (idEscaneo, host, port, proto.upper(), state, service, version))

                # Guardar vulnerabilidades si existen
                if 'script' in portData and 'vulners' in portData['script']:
                    vulnOutput = portData['script']['vulners']
                    vulnInfo += f"\n[VULN] Puerto {port}:\n{vulnOutput}\n"
                    self.guardarVulnerabilidad(cursor, idEscaneo, host, port, proto, vulnOutput)

        if vulnInfo:
            self.resultArea.append("\n[Resultados del script 'vulners']" + vulnInfo)

    # Procesa y guarda las vulnerabilidades extraídas del script 'vulners' en la base de datos
    def guardarVulnerabilidad(self, cursor, idEscaneo, host, port, proto, vulnOutput):
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

            codigoVulnerabilidad = parts[0]  # El identificador puede ser CVE o cualquier otro
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
                INSERT INTO vulnerabilidades 
                (id_escaneo, id_host, puerto, protocolo, codigo_vulnerabilidad, explotable, cvss, descripcion)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (idEscaneo, host, port, proto.upper(), codigoVulnerabilidad, explotable, cvss, descripcion))

    # Muestra un resumen del escaneo
    def summary(self, portStates):
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            # Obtener el ID del escaneo actual
            cursor.execute("SELECT MAX(id) FROM escaneos")
            idEscaneoActual = cursor.fetchone()[0]

            # Obtener la cantidad de vulnerabilidades y explotables del escaneo actual
            cursor.execute("""
                SELECT COUNT(*), SUM(CASE WHEN explotable THEN 1 ELSE 0 END)
                FROM vulnerabilidades
                WHERE id_escaneo = ?
            """, (idEscaneoActual,))
            totalVulnerabilidades, totalExplotables = cursor.fetchone()
            totalVulnerabilidades = totalVulnerabilidades or 0
            totalExplotables = totalExplotables or 0

            resumen = "\nResumen del escaneo:\n"
            resumen += f"Duración del escaneo: {datetime.now() - datetime.fromisoformat(cursor.execute('SELECT fecha_hora FROM escaneos WHERE id = ?', (idEscaneoActual,)).fetchone()[0])}\n"
            for state, count in portStates.items():
                if count > 0:
                    resumen += f"Puertos {state}: {count}\n"
            resumen += f"Total de vulnerabilidades encontradas: {totalVulnerabilidades}\n"
            resumen += f"Total de vulnerabilidades explotables: {totalExplotables}\n"
            self.resultArea.append(resumen)

# Ejecuta la aplicación
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
