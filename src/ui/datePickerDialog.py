from PySide6.QtWidgets import QDialog, QVBoxLayout, QCalendarWidget, QPushButton
from PySide6.QtCore import QDate, Signal
from typing import List

class DatePickerDialog(QDialog):
    dateSelected = Signal(str)  # Señal que se emite cuando se selecciona una fecha

    def __init__(self, availableDates: List[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Seleccionar fecha")
        self.availableDates = {QDate.fromString(date, "yyyy-MM-dd") for date in availableDates}
        self.setupUi()

    def setupUi(self):
        layout = QVBoxLayout(self)

        # Configurar calendario
        self.calendar = QCalendarWidget()
        self.calendar.clicked.connect(self.onDateClicked)

        # Personalizar el calendario para resaltar las fechas disponibles
        self.calendar.clicked.connect(self.checkDateAvailable)
        
        # Establecer el formato de fecha
        self.calendar.setSelectedDate(QDate.currentDate())

        layout.addWidget(self.calendar)

        # Botón para mostrar todas las fechas
        showAllButton = QPushButton("Mostrar todas las fechas")
        showAllButton.setFixedHeight(27)
        showAllButton.setStyleSheet("""
            QPushButton {
                padding: 2px 8px;  /* padding vertical: 2px, horizontal: 8px */
            }
        """)
        showAllButton.clicked.connect(self.acceptAnyDate)
        layout.addWidget(showAllButton)

    def checkDateAvailable(self, date):
        """Verifica si la fecha seleccionada está disponible"""
        if date not in self.availableDates:
            self.calendar.setSelectedDate(QDate.currentDate())
            return False
        return True

    def onDateClicked(self, date):
        """Cuando se hace click en una fecha disponible"""
        if self.checkDateAvailable(date):
            self.dateSelected.emit(date.toString("yyyy-MM-dd"))
            self.accept()

    def acceptAnyDate(self):
        """Cuando se quiere mostrar todas las fechas"""
        self.dateSelected.emit("")
        self.accept()
