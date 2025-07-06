import nmap
import sqlite3
import os
from datetime import datetime
from core.constants import DB_NAME

class NmapScanner:
    @staticmethod
    def _hasRootPrivileges():
        """Verifica si el proceso tiene privilegios de root"""
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False  # No estamos en Unix/Linux
            
    @staticmethod
    def scanTarget(target, scanType, resultCallback=None):
        # Verificar privilegios de root
        hasRoot = NmapScanner._hasRootPrivileges()
        
        # Base de opciones para el escaneo
        baseOptions = "-T5 --script vulners"
        
        # Configurar opciones según privilegios y tipo de escaneo
        if hasRoot:
            if scanType == "UDP":
                options = f"-sUV -O {baseOptions}"  # UDP scan with version detection and OS detection
            else:
                options = f"-sV -O {baseOptions}"   # TCP scan with version detection and OS detection
        else:
            if resultCallback:
                resultCallback("⚠️ No se tienen privilegios de root. El escaneo de sistema operativo será omitido.")
            if scanType == "UDP":
                options = f"-sUV {baseOptions}"  # UDP scan with version detection only
            else:
                options = f"-sV {baseOptions}"   # TCP scan with version detection only
            
        startTime = datetime.now()
        
        if resultCallback:
            resultCallback(f"Iniciando escaneo {scanType} para: {target}")
            resultCallback(f"Argumentos de Nmap: {options}")

        try:
            scanner = nmap.PortScanner()
            scanner.scan(target, arguments=options)

            if not scanner.all_hosts():
                if resultCallback:
                    resultCallback("❌ No se encontraron hosts en el escaneo.\n")
                return None

            endTime = datetime.now()
            tiempoRespuesta = (endTime - startTime).total_seconds()

            return {
                'scanner': scanner,
                'start_time': startTime,
                'response_time': tiempoRespuesta,
                'command': options,
                'has_root': hasRoot
            }

        except nmap.PortScannerError as e:
            if resultCallback:
                resultCallback(f"❌ Error al inicializar el escáner: {e}")
            raise
        except Exception as e:
            if resultCallback:
                resultCallback(f"❌ Error inesperado: {e}")
            raise

class ScanResultProcessor:
    def __init__(self, scanResults, resultCallback=None):
        self.scanResults = scanResults
        self.resultCallback = resultCallback
        self.portStates = {
            "abierto": 0,
            "filtrado": 0,
            "cerrado": 0,
            "abierto|filtrado": 0
        }

    def processResults(self):
        scanner = self.scanResults['scanner']
        
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            # Insertar en escaneos
            cursor.execute("""
                INSERT INTO escaneos (fecha_hora, comando, tiempo_respuesta)
                VALUES (?, ?, ?)
            """, (
                self.scanResults['start_time'].isoformat(sep=' ', timespec='seconds'),
                self.scanResults['command'],
                self.scanResults['response_time']
            ))
            idEscaneo = cursor.lastrowid

            for host in scanner.all_hosts():
                self._processHost(scanner, host, cursor, idEscaneo)

            conn.commit()

        if self.resultCallback:
            self.resultCallback("✅ Datos guardados en la base de datos.")
            self._showSummary()

        return self.portStates

    def _processHost(self, scanner, host, cursor, idEscaneo):
        if self.resultCallback:
            self.resultCallback(f"\nResultados para: {host}")

        # Procesar sistema operativo
        osName = self._processOsInfo(scanner[host])
        
        # Procesar dirección MAC
        macAddress = self._processMacAddress(scanner[host])

        # Insertar información del host
        cursor.execute("""
            INSERT INTO escaneos_host (id_escaneo, id_host, direccion_mac, sistema_operativo)
            VALUES (?, ?, ?, ?)
        """, (idEscaneo, host, macAddress, osName))

        # Procesar puertos y vulnerabilidades
        self._processPorts(scanner[host], host, cursor, idEscaneo)

    def _processOsInfo(self, hostData):
        # Verificar si tenemos privilegios de root del escaneo
        if not self.scanResults.get('has_root', False):
            if self.resultCallback:
                self.resultCallback(" ➤ Sistema operativo: No detectado (se requieren privilegios de root)")
            return None
            
        if 'osmatch' in hostData and hostData['osmatch']:
            osInfo = hostData['osmatch'][0]
            osName = osInfo.get('name', 'Desconocido')
            osAccuracy = osInfo.get('accuracy', '0')
            if self.resultCallback:
                self.resultCallback(f" ➤ Sistema operativo detectado: {osName} (Precisión: {osAccuracy}%)")
            return osName
        else:
            if self.resultCallback:
                self.resultCallback(" ➤ Sistema operativo: No detectado")
            return None

    def _processMacAddress(self, hostData):
        if 'addresses' in hostData and 'mac' in hostData['addresses']:
            macAddress = hostData['addresses']['mac']
            if self.resultCallback:
                self.resultCallback(f" ➤ Dirección MAC: {macAddress}")
            return macAddress
        return None

    def _processPorts(self, hostData, host, cursor, idEscaneo):
        vulnInfo = ""
        
        for proto in hostData.all_protocols():
            ports = hostData[proto].keys()
            for port in ports:
                portData = hostData[proto][port]
                self._processPort(portData, proto, port, host, cursor, idEscaneo, vulnInfo)

        if vulnInfo and self.resultCallback:
            self.resultCallback("\n[Resultados del script 'vulners']" + vulnInfo)

    def _processPort(self, portData, proto, port, host, cursor, idEscaneo, vulnInfo):
        state = portData['state']
        service = portData.get('name', 'desconocido')
        version = portData.get('version', '')

        # Actualizar conteo de puertos
        if state == "open":
            self.portStates["abierto"] += 1
        elif state == "filtered":
            self.portStates["filtrado"] += 1
        elif state == "closed":
            self.portStates["cerrado"] += 1
        elif state == "open|filtered":
            self.portStates["abierto|filtrado"] += 1

        if self.resultCallback:
            self.resultCallback(f"  - [{proto.upper()}] Puerto {port}: {state}, Servicio: {service}, Versión: {version or 'desconocida'}")

        # Guardar información del puerto
        cursor.execute("""
            INSERT INTO escaneos_puertos (id_escaneo, id_host, puerto, protocolo, estado, servicio, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (idEscaneo, host, port, proto.upper(), state, service, version))

        # Procesar vulnerabilidades
        if 'script' in portData and 'vulners' in portData['script']:
            vulnOutput = portData['script']['vulners']
            vulnInfo += f"\n[VULN] Puerto {port}:\n{vulnOutput}\n"
            self._processVulnerabilities(cursor, idEscaneo, host, port, proto, vulnOutput)

    def _processVulnerabilities(self, cursor, idEscaneo, host, port, proto, vulnOutput):
        ignorarPrimeraLinea = True

        for line in vulnOutput.splitlines():
            if ignorarPrimeraLinea:
                ignorarPrimeraLinea = False
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            codigoVulnerabilidad = parts[0]
            cvss = None
            descripcion = ""

            if parts[1].replace('.', '', 1).isdigit():
                cvss = float(parts[1])
                descripcion = " ".join(parts[2:]) if len(parts) > 2 else ""
            else:
                descripcion = " ".join(parts[1:]) if len(parts) > 1 else ""
            
            explotable = "*EXPLOIT*" in descripcion
            descripcion = descripcion.replace("*EXPLOIT*", "").strip()

            cursor.execute("""
                INSERT INTO vulnerabilidades 
                (id_escaneo, id_host, puerto, protocolo, codigo_vulnerabilidad, explotable, cvss, descripcion)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (idEscaneo, host, port, proto.upper(), codigoVulnerabilidad, explotable, cvss, descripcion))

    def _showSummary(self):
        if self.resultCallback is None:
            return
            
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) FROM escaneos")
            idEscaneoActual = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*), SUM(CASE WHEN explotable THEN 1 ELSE 0 END)
                FROM vulnerabilidades
                WHERE id_escaneo = ?
            """, (idEscaneoActual,))
            totalVulnerabilidades, totalExplotables = cursor.fetchone()
            totalVulnerabilidades = totalVulnerabilidades or 0
            totalExplotables = totalExplotables or 0

            resumen = "\n📊 Resumen del escaneo:\n"
            resumen += f"\n⏱️ Duración del escaneo: {datetime.now() - self.scanResults['start_time']}"
            resumen += "\n🔍 Estado de los puertos:\n"
            estadosNombres = {
                "abierto": "Abiertos",
                "filtrado": "Filtrados",
                "cerrado": "Cerrados",
                "abierto|filtrado": "Abiertos y filtrados"
            }
            for state, count in self.portStates.items():
                if count > 0:
                    nombreEstado = estadosNombres.get(state, state)
                    resumen += f"  • Puertos {nombreEstado}: {count}\n"
            resumen += f"Total de vulnerabilidades encontradas: {totalVulnerabilidades}\n"
            resumen += f"Total de vulnerabilidades explotables: {totalExplotables}\n"
            
            self.resultCallback(resumen)
