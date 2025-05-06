CREATE TABLE hosts_puertos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    host TEXT NOT NULL,
    protocolo TEXT NOT NULL,
    puerto INTEGER NOT NULL,
    estado TEXT,
    servicio TEXT,
    version TEXT
);