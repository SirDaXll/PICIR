import sqlite3
import nmap
from datetime import datetime

# Inicializar el escáner
scanner = nmap.PortScanner()
target = "scanme.nmap.org"

try:
    # Realizar el escaneo
    scanner.scan(target)
    if not scanner.all_hosts():
        print("No se encontraron hosts en el escaneo.")
        exit()

    # Obtener fecha y hora actual
    fecha_hora = datetime.now().isoformat(sep=' ', timespec='seconds')

    # Conectar a la base de datos
    with sqlite3.connect("hosts_puertos.db") as conn:
        cursor = conn.cursor()

        # Procesar y guardar resultados
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    estado = scanner[host][proto][port]['state']
                    servicio = scanner[host][proto][port].get('name', 'desconocido')
                    version = scanner[host][proto][port].get('version', 'desconocida')

                    cursor.execute("""
                        INSERT INTO hosts_puertos (fecha_hora, host, protocolo, puerto, estado, servicio, version)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (fecha_hora, host, proto.upper(), port, estado, servicio, version))

    print("Datos guardados en la base de datos.")

except nmap.PortScannerError as e:
    print(f"Error al inicializar el escáner: {e}")
except sqlite3.Error as e:
    print(f"Error al interactuar con la base de datos: {e}")
except Exception as e:
    print(f"Error inesperado: {e}")