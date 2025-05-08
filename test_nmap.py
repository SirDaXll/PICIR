import sqlite3
import nmap
from datetime import datetime
from collections import Counter

# Solicitar al usuario el target
target = input("Ingrese la IP o nombre del host a escanear (Deje vacío para usar scanme.nmap.org): ").strip()
if not target:
    target = "scanme.nmap.org"

# Inicializar el escáner
scanner = nmap.PortScanner()

# Contador para resumen final
estado_puertos = Counter()

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
            print(f"\nResultados para: {host}")
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    estado = scanner[host][proto][port]['state']
                    
                    # Obtener valores desde Nmap (pueden ser vacíos o no existir)
                    servicio_raw = scanner[host][proto][port].get('name', '')
                    version_raw = scanner[host][proto][port].get('version', '')

                    # Preparar valores para mostrar en pantalla
                    servicio_mostrar = servicio_raw if servicio_raw else 'desconocido'
                    version_mostrar = version_raw if version_raw else 'desconocida'

                    # Mostrar resultados al usuario
                    print(f"  - [{proto.upper()}] Puerto {port}: {estado}, Servicio: {servicio_mostrar}, Versión: {version_mostrar}")

                    # Guardar valores crudos en la base de datos (vacíos si no hay)
                    cursor.execute("""
                        INSERT INTO hosts_puertos (fecha_hora, host, protocolo, puerto, estado, servicio, version)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (fecha_hora, host, proto.upper(), port, estado, servicio_raw, version_raw))

                    # Contar el estado del puerto
                    estado_puertos[estado] += 1

    # Resumen final
    print("\nResumen del escaneo:")
    total = sum(estado_puertos.values())
    for estado, cantidad in estado_puertos.items():
        print(f" - {estado.title()}: {cantidad}")
    print(f" Total de puertos escaneados: {total}")

    print("\n✅ Datos guardados en la base de datos.")

except nmap.PortScannerError as e:
    print(f"❌ Error al inicializar el escáner: {e}")
except sqlite3.Error as e:
    print(f"❌ Error al interactuar con la base de datos: {e}")
except Exception as e:
    print(f"❌ Error inesperado: {e}")