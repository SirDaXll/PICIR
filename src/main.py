"""
PICIR - Plataforma Integral de Ciberseguridad para Infraestructura de Red
Aplicación para realizar escaneos de red usando nmap y gestionar los resultados.
Más pronto.
"""

import sys
from PySide6.QtWidgets import QApplication
from ui.mainWindow import MainWindow

def main():
    """Punto de entrada principal de la aplicación"""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
