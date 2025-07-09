from PySide6.QtWidgets import QDialog, QVBoxLayout, QCalendarWidget, QPushButton
from PySide6.QtCore import QDate, Signal
from typing import List


class DatePickerDialog(QDialog):
    """Diálogo para seleccionar una fecha de un conjunto de fechas disponibles."""

    date_selected = Signal(str)  # Señal que se emite cuando se selecciona una fecha

    def __init__(self, available_dates: List[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Seleccionar fecha")
        self.available_dates = {
            QDate.fromString(date, "yyyy-MM-dd") for date in available_dates
        }
        self.setup_ui()

    def setup_ui(self):
        """Configura la interfaz de usuario del diálogo."""
        layout = QVBoxLayout(self)

        # Configurar calendario
        self.calendar = QCalendarWidget()
        self.calendar.clicked.connect(self.on_date_clicked)

        # Personalizar el calendario para resaltar las fechas disponibles
        self.calendar.clicked.connect(self.check_date_available)
        
        # Establecer el formato de fecha
        self.calendar.setSelectedDate(QDate.currentDate())

        layout.addWidget(self.calendar)

        # Botón para mostrar todas las fechas
        show_all_button = QPushButton("Mostrar todas las fechas")
        show_all_button.setFixedHeight(27)
        show_all_button.setStyleSheet("""
            QPushButton {
                padding: 2px 8px;  /* padding vertical: 2px, horizontal: 8px */
            }
        """)
        show_all_button.clicked.connect(self.accept_any_date)
        layout.addWidget(show_all_button)

    def check_date_available(self, date: QDate) -> bool:
        """Verifica si la fecha seleccionada está disponible.
        
        Args:
            date: Fecha a verificar

        Returns:
            bool: True si la fecha está disponible, False en caso contrario
        """
        if date not in self.available_dates:
            self.calendar.setSelectedDate(QDate.currentDate())
            return False
        return True

    def on_date_clicked(self, date: QDate) -> None:
        """Maneja el evento de click en una fecha.
        
        Args:
            date: Fecha seleccionada
        """
        if self.check_date_available(date):
            self.date_selected.emit(date.toString("yyyy-MM-dd"))
            self.accept()

    def accept_any_date(self) -> None:
        """Emite una señal para mostrar todas las fechas."""
        self.date_selected.emit("")
        self.accept()
