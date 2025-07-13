import nmap
import sqlite3
import os
import socket
from datetime import datetime
from core.constants import DB_NAME


def check_internet_connection():
    """Verifica si hay conexión a internet intentando conectarse a un servidor confiable.
    
    Returns:
        bool: True si hay conexión a internet, False en caso contrario.
    """
    try:
        # Intentar conectarse a Google DNS
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False


class NmapScanner:
    @staticmethod
    def _has_root_privileges():
        """Verifica si el proceso tiene privilegios de root"""
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False  # No estamos en Unix/Linux

    @staticmethod
    def scan_target(target, scan_type, result_callback=None, options=None):
        """Realiza un escaneo de red con Nmap.

        Args:
            target: IP o rango de IPs a escanear
            scan_type: Tipo de escaneo ("TCP" o "UDP")
            result_callback: Función opcional para recibir actualizaciones
            options: Lista de opciones adicionales de nmap (ejemplo: ["-sV", "-O", "--script vulners"])

        Returns:
            Diccionario con los resultados del escaneo o None si no se encontraron hosts
        """
        # Verificar privilegios de root
        has_root = NmapScanner._has_root_privileges()
        
        # Si se va a usar el script vulners, verificar conexión a internet
        if options and "--script vulners" in options:
            if not check_internet_connection():
                if result_callback:
                    result_callback(
                        "⚠️ No hay conexión a internet. "
                        "El escaneo de vulnerabilidades será omitido."
                    )
                # Remover script vulners de las opciones
                options = [opt for opt in options if opt != "--script vulners"]
        
        if not has_root and ("-O" in (options or []) or "-sU" in (options or [])):
            if result_callback:
                result_callback(
                    "⚠️ No se tienen privilegios de root. "
                    "El escaneo de sistema operativo y UDP será omitido."
                )
            # Remover opciones que requieren root
            if options:
                options = [opt for opt in options if opt not in ["-O", "-sU"]]
        
        # Si se proporcionaron opciones, usarlas directamente
        if options:
            scan_options = " ".join(options)
        else:
            # Usar opciones por defecto si no se proporcionaron
            scan_options = "-sV -T5"
            
        start_time = datetime.now()
        
        if result_callback:
            result_callback(f"Iniciando escaneo {scan_type} para: {target}")
            result_callback(f"Argumentos de Nmap: {scan_options}")

        try:
            scanner = nmap.PortScanner()
            scanner.scan(target, arguments=scan_options)

            if not scanner.all_hosts():
                if result_callback:
                    result_callback("❌ No se encontraron hosts en el escaneo.\n")
                return None

            end_time = datetime.now()
            tiempo_respuesta = (end_time - start_time).total_seconds()

            return {
                'scanner': scanner,
                'start_time': start_time,
                'response_time': tiempo_respuesta,
                'command': ' '.join(options) if options else '',  # Convert list to string
                'has_root': has_root
            }

        except nmap.PortScannerError as e:
            if result_callback:
                result_callback(f"❌ Error al inicializar el escáner: {e}")
            raise
        except Exception as e:
            if result_callback:
                result_callback(f"❌ Error inesperado: {e}")
            raise


class ScanResultProcessor:
    def __init__(self, scan_results, result_callback=None):
        self.scan_results = scan_results
        self.result_callback = result_callback
        self.port_states = {
            "abierto": 0,
            "filtrado": 0,
            "cerrado": 0,
            "abierto|filtrado": 0
        }
        # Comprobar si el script vulners está en las opciones de escaneo
        self.vulners_enabled = '--script vulners' in (self.scan_results.get('command', '') or '')

    def process_results(self):
        """Procesa y guarda los resultados del escaneo en la base de datos."""
        scanner = self.scan_results['scanner']
        
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            # Insertar en escaneos
            cursor.execute("""
                INSERT INTO escaneos (fecha_hora, comando, tiempo_respuesta)
                VALUES (?, ?, ?)
            """, (
                self.scan_results['start_time'].isoformat(sep=' ', timespec='seconds'),
                self.scan_results['command'],
                self.scan_results['response_time']
            ))
            scan_id = cursor.lastrowid

            # Procesar cada host escaneado
            for host in scanner.all_hosts():
                if self.result_callback:
                    self.result_callback(f"\nProcesando host: {host}")

                # Obtener información del sistema operativo si está disponible
                os_info = None
                if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                    os_match = scanner[host]['osmatch'][0]
                    os_info = f"{os_match['name']} ({os_match['accuracy']}%)"
                    if self.result_callback:
                        self.result_callback(f"Sistema operativo detectado: {os_info}")

                # Insertar información del host
                cursor.execute("""
                    INSERT INTO escaneos_host (id_escaneo, id_host, direccion_mac, sistema_operativo)
                    VALUES (?, ?, ?, ?)
                """, (
                    scan_id,
                    host,
                    scanner[host].get('mac', None) if 'mac' in scanner[host] else None,
                    os_info
                ))

                # Procesar puertos para cada protocolo
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        port_info = scanner[host][proto][port]
                        state = port_info['state']
                        service = port_info.get('name', '')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        extrainfo = port_info.get('extrainfo', '')

                        # Incrementar contador del estado del puerto
                        state_key = state.lower().replace(' ', '')
                        if state_key in self.port_states:
                            self.port_states[state_key] += 1

                        # Formatear versión completa del servicio
                        full_version = service
                        if product:
                            full_version += f" {product}"
                        if version:
                            full_version += f" {version}"
                        if extrainfo:
                            full_version += f" ({extrainfo})"

                        if self.result_callback:
                            state_name = {
                                "open": "abierto",
                                "filtered": "filtrado",
                                "closed": "cerrado",
                                "open|filtered": "abierto|filtrado"
                            }.get(state, state)
                            self.result_callback(
                                f"Puerto {port}/{proto} - Estado: {state_name} - "
                                f"Servicio: {full_version}"
                            )

                        # Insertar información del puerto
                        cursor.execute("""
                            INSERT INTO escaneos_puertos (
                                id_escaneo, id_host, puerto, protocolo,
                                estado, servicio, version
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (
                            scan_id, host, port, proto, state,
                            service, full_version
                        ))

                        # Procesar vulnerabilidades del puerto si las hay
                        if 'script' in port_info and 'vulners' in port_info['script']:
                            ignore_first_line = True
                            vulners_output = port_info['script']['vulners']
                            
                            for line in vulners_output.split('\n'):
                                if ignore_first_line:
                                    ignore_first_line = False
                                    continue
                                    
                                if not line.strip():
                                    continue
                                    
                                try:
                                    parts = line.strip().split('\t')
                                    if len(parts) >= 2:
                                        cve_id = parts[0].strip()
                                        cvss = float(parts[1].strip())
                                        url = parts[2].strip() if len(parts) > 2 else ""
                                        
                                        cursor.execute("""
                                            INSERT INTO vulnerabilidades (
                                                id_escaneo, id_host, puerto, protocolo,
                                                codigo_vulnerabilidad, explotable,
                                                cvss, descripcion
                                            )
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                        """, (
                                            scan_id, host, port, proto,
                                            cve_id, cvss >= 7.0, cvss, url
                                        ))
                                except ValueError:
                                    if self.result_callback:
                                        self.result_callback(
                                            f"⚠️ Error al procesar vulnerabilidad: {line}"
                                        )

            # Obtener estadísticas
            cursor.execute("""
                SELECT id FROM escaneos WHERE id = ?
            """, (scan_id,))
            current_scan_id = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*), COUNT(CASE WHEN explotable THEN 1 END)
                FROM vulnerabilidades
                WHERE id_escaneo = ?
            """, (current_scan_id,))
            total_vulns, total_exploitable = cursor.fetchone()
            total_vulns = total_vulns or 0
            total_exploitable = total_exploitable or 0

            if self.result_callback:
                self.result_callback("\nResumen del escaneo:")
                self.result_callback(f"Total de hosts escaneados: {len(scanner.all_hosts())}")
                state_names = {
                    "abierto": "abiertos",
                    "filtrado": "filtrados",
                    "cerrado": "cerrados",
                    "abierto|filtrado": "abiertos/filtrados"
                }
                for state, count in self.port_states.items():
                    if count > 0:
                        state_name = state_names.get(state, state)
                        self.result_callback(f"Puertos {state_name}: {count}")
                # Solo mostrar el resumen de vulnerabilidades si el script vulners estaba habilitado
                if self.vulners_enabled:
                    self.result_callback(f"Vulnerabilidades detectadas: {total_vulns}")
                    self.result_callback(f"Vulnerabilidades explotables: {total_exploitable}")
