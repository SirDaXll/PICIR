CREATE TABLE escaneos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    host TEXT NOT NULL,
    comando TEXT NOT NULL,
    sistema_operativo TEXT
);

CREATE TABLE puertos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    escaneo_id INTEGER NOT NULL,
    protocolo TEXT NOT NULL,
    puerto INTEGER NOT NULL,
    estado TEXT,
    servicio TEXT,
    version TEXT,
    FOREIGN KEY (escaneo_id) REFERENCES escaneos(id)
);

CREATE TABLE vulnerabilidades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    puerto_id INTEGER NOT NULL,
    id_vulnerabilidad TEXT NOT NULL,
    explotable BOOLEAN,
    cvss REAL,
    descripcion TEXT,
    FOREIGN KEY (puerto_id) REFERENCES puertos(id)
);