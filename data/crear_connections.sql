--REFERENCIA A LA BASE DE DATOS REMOTA dionaea.sqlite
CREATE TABLE "connections" {
    connection INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_type TEXT,
    connection_transport TEXT,
    connection_protocol TEXT,
    connection_timestamp INTEGER,
    connection_root INTEGER,
    connection_parent INTEGER,
    local_host TEXT,
    local_port INTEGER,
    remote_host TEXT,
    remote_hostname TEXT,
    remote_port INTEGER,
}