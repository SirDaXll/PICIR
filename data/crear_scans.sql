CREATE TABLE escaneos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    comando TEXT NOT NULL,
    tiempo_respuesta REAL
);

CREATE TABLE escaneos_host (
    id_escaneo INTEGER NOT NULL,
    id_host TEXT NOT NULL,
    direccion_mac TEXT,
    sistema_operativo TEXT,
    PRIMARY KEY (id_escaneo, id_host),
    FOREIGN KEY (id_escaneo) REFERENCES escaneos(id)
);

CREATE TABLE escaneos_puertos (
    id_escaneo INTEGER NOT NULL,
    id_host TEXT NOT NULL,
    puerto INTEGER NOT NULL,
    protocolo TEXT NOT NULL,
    estado TEXT,
    servicio TEXT,
    version TEXT,
    PRIMARY KEY (id_escaneo, id_host, puerto, protocolo),
    FOREIGN KEY (id_escaneo, id_host) REFERENCES escaneos_host(id_escaneo, id_host)
);

CREATE TABLE vulnerabilidades (
    id_escaneo INTEGER NOT NULL,
    id_host TEXT NOT NULL,
    puerto INTEGER NOT NULL,
    protocolo TEXT NOT NULL,
    id_vulnerabilidad INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo_vulnerabilidad TEXT NOT NULL,
    explotable BOOLEAN,
    cvss REAL,
    descripcion TEXT,
    FOREIGN KEY (id_escaneo, id_host, puerto, protocolo)
        REFERENCES escaneos_puertos(id_escaneo, id_host, puerto, protocolo)
);