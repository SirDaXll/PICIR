import sqlite3
from typing import Optional, List, Dict, Any
from core.constants import DB_NAME


class RecordManager:
    @staticmethod
    def search_records(date_filter: Optional[str] = None,
                      ip_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Busca registros de escaneos aplicando los filtros especificados.

        Args:
            date_filter: Filtro de fecha en formato YYYY-MM-DD
            ip_filter: Filtro de dirección IP

        Returns:
            Lista de diccionarios con la información de los escaneos encontrados
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT 
                        e.id,
                        e.fecha_hora,
                        eh.id_host,
                        eh.direccion_mac,
                        eh.sistema_operativo,
                        COUNT(DISTINCT ep.puerto) as total_puertos,
                        COUNT(DISTINCT v.id_vulnerabilidad) as total_vulnerabilidades,
                        COUNT(DISTINCT CASE WHEN v.explotable THEN v.id_vulnerabilidad END) as vulnerabilidades_explotables
                    FROM escaneos e
                    LEFT JOIN escaneos_host eh ON e.id = eh.id_escaneo
                    LEFT JOIN escaneos_puertos ep ON eh.id_escaneo = ep.id_escaneo
                        AND eh.id_host = ep.id_host
                    LEFT JOIN vulnerabilidades v ON ep.id_escaneo = v.id_escaneo 
                        AND ep.id_host = v.id_host 
                        AND ep.puerto = v.puerto 
                        AND ep.protocolo = v.protocolo
                    WHERE 1=1
                """
                params = []
                
                if date_filter:
                    query += " AND DATE(e.fecha_hora) = ?"
                    params.append(date_filter)
                
                if ip_filter:
                    query += " AND eh.id_host LIKE ?"
                    params.append(f"%{ip_filter}%")
                
                query += """
                    GROUP BY e.id, eh.id_host
                    ORDER BY e.fecha_hora DESC
                """
                
                cursor.execute(query, params)
                records = cursor.fetchall()
                
                return [
                    {
                        "id": record[0],
                        "fecha": record[1],
                        "ip_host": record[2],
                        "mac_address": record[3] or "No detectada",
                        "sistema_operativo": record[4] or "No detectado",
                        "puertos_abiertos": record[5] or 0,
                        "vulnerabilidades": record[6] or 0,
                        "vulnerabilidades_explotables": record[7] or 0
                    }
                    for record in records
                ]

        except sqlite3.Error as e:
            raise Exception(f"Error al consultar la base de datos: {e}")
        except Exception as e:
            raise Exception(f"Error inesperado: {e}")

    @staticmethod
    def get_scan_details(scan_id: int, host_ip: str) -> Dict[str, Any]:
        """Obtiene los detalles completos de un escaneo específico.

        Args:
            scan_id: ID del escaneo a consultar
            host_ip: Dirección IP del host escaneado

        Returns:
            Diccionario con toda la información del escaneo
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                
                # Obtener información general del escaneo
                query = """
                    SELECT 
                        e.fecha_hora,
                        e.comando,
                        e.tiempo_respuesta,
                        eh.id_host,
                        eh.direccion_mac,
                        eh.sistema_operativo
                    FROM escaneos e
                    JOIN escaneos_host eh ON e.id = eh.id_escaneo
                    WHERE e.id = ? AND eh.id_host = ?
                """
                cursor.execute(query, (scan_id, host_ip))
                general_info = cursor.fetchone()
                
                if not general_info:
                    raise Exception("No se encontró el escaneo especificado")
                
                # Obtener puertos abiertos
                query = """
                    SELECT 
                        puerto,
                        protocolo,
                        servicio,
                        version
                    FROM escaneos_puertos
                    WHERE id_escaneo = ? AND id_host = ?
                """
                cursor.execute(query, (scan_id, host_ip))
                ports = cursor.fetchall()
                
                # Obtener vulnerabilidades
                query = """
                    SELECT 
                        id_vulnerabilidad,
                        puerto,
                        protocolo,
                        descripcion,
                        explotable,
                        cvss
                    FROM vulnerabilidades
                    WHERE id_escaneo = ? AND id_host = ?
                """
                cursor.execute(query, (scan_id, host_ip))
                vulnerabilities = cursor.fetchall()
                
                return {
                    "general": {
                        "fecha": general_info[0],
                        "comando": general_info[1],
                        "tiempo_respuesta": general_info[2],
                        "ip_host": general_info[3],
                        "mac_address": general_info[4] or "No detectada",
                        "sistema_operativo": general_info[5] or "No detectado"
                    },
                    "puertos": [
                        {
                            "puerto": port[0],
                            "protocolo": port[1],
                            "servicio": port[2],
                            "version": port[3]
                        }
                        for port in ports
                    ],
                    "vulnerabilidades": [
                        {
                            "id": vuln[0],
                            "puerto": vuln[1],
                            "protocolo": vuln[2],
                            "descripcion": vuln[3],
                            "explotable": bool(vuln[4]),
                            "cvss": float(vuln[5]) if vuln[5] is not None else 0.0
                        }
                        for vuln in vulnerabilities
                    ]
                }

        except sqlite3.Error as e:
            raise Exception(f"Error al consultar la base de datos: {e}")
        except Exception as e:
            raise Exception(f"Error inesperado: {e}")

    @staticmethod
    def get_available_dates() -> List[str]:
        """Obtiene todas las fechas en las que hay escaneos registrados.

        Returns:
            Lista de fechas en formato YYYY-MM-DD
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                query = """
                    SELECT DISTINCT DATE(fecha_hora) as fecha
                    FROM escaneos
                    ORDER BY fecha DESC
                """
                cursor.execute(query)
                return [date[0] for date in cursor.fetchall()]
        except sqlite3.Error as e:
            raise Exception(f"Error al consultar la base de datos: {e}")
        except Exception as e:
            raise Exception(f"Error inesperado: {e}")

    @staticmethod
    def save_results(scan_results: Dict[str, Any], target: str) -> None:
        """Guarda los resultados del escaneo en la base de datos.

        Args:
            scan_results: Diccionario con los resultados del escaneo
            target: Dirección IP o rango de IPs objetivo del escaneo
        """
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                
                # 1. Insertar el escaneo
                cursor.execute("""
                    INSERT INTO escaneos (fecha_hora, comando, tiempo_respuesta)
                    VALUES (CURRENT_TIMESTAMP, ?, ?)
                """, (scan_results.get('command', ''), scan_results.get('elapsed', 0)))
                
                scan_id = cursor.lastrowid
                
                # 2. Insertar información del host
                for host in scan_results.get('hosts', []):
                    # Insertar host
                    cursor.execute("""
                        INSERT INTO escaneos_host (id_escaneo, id_host, sistema_operativo)
                        VALUES (?, ?, ?)
                    """, (scan_id, host.get('ip', target), host.get('os', None)))
                    
                    # 3. Insertar puertos
                    for port in host.get('ports', []):
                        cursor.execute("""
                            INSERT INTO escaneos_puertos (
                                id_escaneo, id_host, puerto, protocolo, servicio, version
                            )
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (scan_id, host.get('ip', target), port.get('port'),
                              port.get('protocol'), port.get('service'),
                              port.get('version')))
                        
                        # 4. Insertar vulnerabilidades
                        for vuln in port.get('vulnerabilities', []):
                            cursor.execute("""
                                INSERT INTO vulnerabilidades (
                                    id_escaneo, id_host, puerto, protocolo,
                                    codigo_vulnerabilidad, explotable, cvss, descripcion
                                )
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """, (scan_id, host.get('ip', target), port.get('port'),
                                  port.get('protocol'), vuln.get('code', ''),
                                  vuln.get('exploitable', False), vuln.get('cvss', 0.0),
                                  vuln.get('description', '')))

        except sqlite3.Error as e:
            raise Exception(f"Error al guardar en la base de datos: {e}")
        except Exception as e:
            raise Exception(f"Error inesperado: {e}")
