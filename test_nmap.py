import sqlite3
import nmap
from datetime import datetime
from collections import Counter

# Constantes.
DB_NAME = "hosts_puertos.db"
DEFAULT_TARGET = "scanme.nmap.org"

# Solicita al usuario el target a escanear.
def obtener_target():
    target = input("Ingrese la IP o nombre del host a escanear (Deje vacío para usar scanme.nmap.org): ").strip()
    return target if target else DEFAULT_TARGET

# Realiza el escaneo con Nmap y retorna los resultados.
def realizar_escaneo(scanner, target):
    scanner.scan(target)
    if not scanner.all_hosts():
        print("No se encontraron hosts en el escaneo.")
        return None
    return scanner

# Guarda los resultados del escaneo en la base de datos.
def guardar_resultados(cursor, fecha_hora, host, proto, port, estado, servicio, version):
    cursor.execute("""
        INSERT INTO hosts_puertos (fecha_hora, host, protocolo, puerto, estado, servicio, version)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (fecha_hora, host, proto.upper(), port, estado, servicio, version))

# Procesa los resultados del escaneo y los guarda en la base de datos.
def procesar_resultados(scanner, conn, fecha_hora):
    estado_puertos = Counter()
    cursor = conn.cursor()

    for host in scanner.all_hosts():
        print(f"\nResultados para: {host}")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                estado = scanner[host][proto][port]['state']
                servicio = scanner[host][proto][port].get('name', 'desconocido')
                
                # Obtener la versión para la base de datos y para mostrar al usuario.
                version_db = scanner[host][proto][port].get('version', '')  # Vacío para la base de datos.
                version_display = version_db if version_db else "desconocida"  # "desconocida" para el usuario.

                # Mostrar resultados al usuario.
                print(f"  - [{proto.upper()}] Puerto {port}: {estado}, Servicio: {servicio}, Versión: {version_display}")

                # Guardar en la base de datos.
                guardar_resultados(cursor, fecha_hora, host, proto, port, estado, servicio, version_db)

                # Contar el estado del puerto.
                estado_puertos[estado] += 1

    return estado_puertos

# Muestra un resumen del escaneo.
def mostrar_resumen(estado_puertos):
    print("\nResumen del escaneo:")
    total = sum(estado_puertos.values())
    for estado, cantidad in estado_puertos.items():
        print(f" - {estado.title()}: {cantidad}")
    print(f" Total de puertos escaneados: {total}")

# Inicializar el escáner.
def main():
    scanner = nmap.PortScanner()
    target = obtener_target()

    try:
        # Realizar el escaneo.
        resultados = realizar_escaneo(scanner, target)
        if not resultados:
            return

        # Obtener fecha y hora actual.
        fecha_hora = datetime.now().isoformat(sep=' ', timespec='seconds')

        # Conectar a la base de datos.
        with sqlite3.connect(DB_NAME) as conn:
            estado_puertos = procesar_resultados(resultados, conn, fecha_hora)

        # Mostrar resumen.
        mostrar_resumen(estado_puertos)
        print("\n✅ Datos guardados en la base de datos.")

    except nmap.PortScannerError as e:
        print(f"❌ Error al inicializar el escáner: {e}")
    except sqlite3.Error as e:
        print(f"❌ Error al interactuar con la base de datos: {e}")
    except Exception as e:
        print(f"❌ Error inesperado: {e}")

if __name__ == "__main__":
    main()