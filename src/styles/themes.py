# Estilos para el tema oscuro
DARK_THEME = """
QMainWindow {
    background-color: #2b2b2b;
}
QLabel {
    color: #ffffff;
    font-size: 14px;
    margin-bottom: 5px;
}
QLineEdit, QComboBox {
    padding: 8px;
    border: 2px solid #3d3d3d;
    border-radius: 4px;
    background-color: #363636;
    color: #ffffff;
    font-size: 13px;
}
QComboBox {
    min-width: 80px;
}
QComboBox#themeSelector {
    min-width: 80px;
}
QPushButton {
    padding: 10px 20px;
    background-color: #007acc;
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 14px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #005999;
}
QTextEdit {
    background-color: #1e1e1e;
    color: #ffffff;
    border: 2px solid #3d3d3d;
    border-radius: 4px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    padding: 8px;
}
QLabel#previewLabel {
    background-color: #1e1e1e;
    color: #00ff00;
    padding: 10px;
    border: 1px solid #3d3d3d;
    border-radius: 4px;
    font-family: 'Consolas', 'Courier New', monospace;
}
"""

# Estilos para el tema claro
LIGHT_THEME = """
QMainWindow {
    background-color: #f4f4f4;
}
QLabel {
    color: #000000;
    font-size: 14px;
    margin-bottom: 5px;
}
QLineEdit, QComboBox {
    padding: 8px;
    border: 2px solid #c2c2c2;
    border-radius: 4px;
    background-color: #c9c9c9;
    color: #000000;
    font-size: 13px;
}
QComboBox {
    min-width: 80px;
}
QComboBox QAbstractItemView {
    background-color: #c9c9c9;
    color: #000000;
    selection-background-color: #007acc;
    selection-color: #ffffff;
    border: 1px solid #c2c2c2;
}
QComboBox#themeSelector {
    min-width: 80px;
}
QPushButton {
    padding: 10px 20px;
    background-color: #007acc;
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 14px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #005999;
}
QTextEdit {
    background-color: #e1e1e1;
    color: #000000;
    border: 2px solid #c2c2c2;
    border-radius: 4px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    padding: 8px;
}
QTabWidget::pane {
    border: 1px solid #c2c2c2;
    background-color: #f4f4f4;
    top: -1px;
}
QTabBar::tab {
    background-color: #c9c9c9;
    color: #000000;
    padding: 8px 12px;
    border: 1px solid #c2c2c2;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #f4f4f4;
    border-bottom: none;
}
QTabBar::tab:hover:!selected {
    background-color: #d9d9d9;
}
QLabel#previewLabel {
    background-color: #e1e1e1;
    color: #000000;
    padding: 10px;
    border: 1px solid #c2c2c2;
    border-radius: 4px;
    font-family: 'Consolas', 'Courier New', monospace;
}
"""
