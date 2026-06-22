<?php
/**
 * Sistema de Protección para Múltiples Bases de Datos MySQL
 * @author Backend
 * @version 2.0
 */
class DatabaseProtectionSystem {
    
    private $connectionManager;
    private $securityLog = [];
    private $encryptionKey;
    private $blockedIPs = [];
    private $failedAttempts = [];
    private $allowedTables = [];
    private $queryPatterns = [];
    
    // Configuración de protección
    private $config = [
        'max_failed_attempts' => 5,
        'block_time_minutes' => 30,
        'enable_query_logging' => true,
        'enable_sql_injection_detection' => true,
        'enable_xss_protection' => true,
        'max_query_length' => 10000,
        'forbidden_keywords' => [
            'DROP', 'TRUNCATE', 'ALTER', 'CREATE', 'DELETE', 
            'UPDATE', 'INSERT', 'RENAME', 'GRANT', 'REVOKE'
        ],
        'sensitive_tables' => [
            'users', 'passwords', 'tokens', 'sessions', 'credentials'
        ]
    ];
    
    /**
     * Constructor
     * @param MySQLConnectionManager $connectionManager
     * @param string $encryptionKey Clave para encriptación
     */
    public function __construct($connectionManager, $encryptionKey = null) {
        $this->connectionManager = $connectionManager;
        $this->encryptionKey = $encryptionKey ?? $this->generateEncryptionKey();
        $this->loadBlockedIPs();
        $this->initializeProtectionPatterns();
    }
    
    /**
     * Inicializa patrones de protección
     */
    private function initializeProtectionPatterns() {
        // Patrones de SQL Injection
        $this->queryPatterns = [
            'union_select' => '/\bUNION\b.*\bSELECT\b/i',
            'xor_injection' => '/\bXOR\b/i',
            'boolean_injection' => "/'.*?(OR|AND).*?'/i",
            'comment_injection' => '/--|\/\*|\*\/|#/',
            'stacked_queries' => '/;.*?(DROP|DELETE|INSERT|UPDATE)/i',
            'sleep_injection' => '/\bSLEEP\s*\(/i',
            'benchmark_injection' => '/\bBENCHMARK\s*\(/i',
            'information_schema' => '/information_schema/i'
        ];
    }
    
    /**
     * Genera clave de encriptación
     */
    private function generateEncryptionKey() {
        return bin2hex(openssl_random_pseudo_bytes(32));
    }
    
    /**
     * Carga IPs bloqueadas desde archivo
     */
    private function loadBlockedIPs() {
        if (file_exists('blocked_ips.json')) {
            $data = json_decode(file_get_contents('blocked_ips.json'), true);
            $this->blockedIPs = $data['ips'] ?? [];
        }
    }
    
    /**
     * Guarda IPs bloqueadas
     */
    private function saveBlockedIPs() {
        file_put_contents('blocked_ips.json', json_encode([
            'ips' => $this->blockedIPs,
            'last_update' => date('Y-m-d H:i:s')
        ]));
    }
    
    /**
     * Verifica si una IP está bloqueada
     */
    private function isIPBlocked($ip) {
        if (isset($this->blockedIPs[$ip])) {
            $blockUntil = $this->blockedIPs[$ip];
            if (time() < $blockUntil) {
                return true;
            } else {
                unset($this->blockedIPs[$ip]);
                $this->saveBlockedIPs();
            }
        }
        return false;
    }
    
    /**
     * Registra intento fallido
     */
    private function logFailedAttempt($ip, $reason, $query = null) {
        if (!isset($this->failedAttempts[$ip])) {
            $this->failedAttempts[$ip] = [];
        }
        
        $this->failedAttempts[$ip][] = [
            'time' => time(),
            'reason' => $reason,
            'query' => $query
        ];
        
        // Limpiar intentos antiguos (última hora)
        $this->failedAttempts[$ip] = array_filter($this->failedAttempts[$ip], function($attempt) {
            return $attempt['time'] > (time() - 3600);
        });
        
        // Bloquear IP si excede intentos
        if (count($this->failedAttempts[$ip]) >= $this->config['max_failed_attempts']) {
            $this->blockedIPs[$ip] = time() + ($this->config['block_time_minutes'] * 60);
            $this->saveBlockedIPs();
            $this->logSecurityEvent("IP bloqueada: $ip por $this->config[block_time_minutes] minutos");
        }
    }
    
    /**
     * Registra evento de seguridad
     */
    private function logSecurityEvent($event, $severity = 'WARNING') {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'severity' => $severity,
            'event' => $event,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ];
        
        $this->securityLog[] = $logEntry;
        
        // Guardar en archivo
        file_put_contents('security_log.json', json_encode($this->securityLog, JSON_PRETTY_PRINT));
        
        // Notificar si es crítico
        if ($severity === 'CRITICAL') {
            $this->sendAlert($event);
        }
    }
    
    /**
     * Envía alerta de seguridad
     */
    private function sendAlert($message) {
        // Configurar método de alerta (email, webhook, etc.)
        $webhookUrl = $this->config['alert_webhook'] ?? null;
        if ($webhookUrl) {
            file_get_contents($webhookUrl . '?message=' . urlencode($message));
        }
    }
    
    /**
     * Detecta SQL Injection en consulta
     */
    private function detectSQLInjection($query) {
        $query = strtoupper($query);
        
        foreach ($this->queryPatterns as $patternName => $pattern) {
            if (preg_match($pattern, $query)) {
                return "Posible SQL Injection detectada: $patternName";
            }
        }
        
        // Verificar palabras prohibidas en contexto peligroso
        foreach ($this->config['forbidden_keywords'] as $keyword) {
            if (preg_match("/\b$keyword\b/i", $query) && 
                !preg_match("/^\s*SELECT.*\b$keyword\b.*FROM/i", $query)) {
                return "Palabra prohibida en contexto peligroso: $keyword";
            }
        }
        
        return false;
    }
    
    /**
     * Detecta XSS en datos
     */
    private function detectXSS($data) {
        if (!$this->config['enable_xss_protection']) {
            return false;
        }
        
        $patterns = [
            '/<script\b[^>]*>(.*?)<\/script>/is',
            '/javascript:/i',
            '/on\w+\s*=/i',
            '/<iframe\b/i',
            '/<object\b/i',
            '/<embed\b/i',
            '/expression\s*\(/i'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $data)) {
                return "Posible XSS detectado";
            }
        }
        
        return false;
    }
    
    /**
     * Escapa datos para prevenir XSS
     */
    private function sanitizeData($data) {
        if (is_array($data)) {
            return array_map([$this, 'sanitizeData'], $data);
        }
        
        if (is_string($data)) {
            // Eliminar tags HTML peligrosos
            $data = strip_tags($data, '<p><br><b><strong><em><i>');
            // Convertir caracteres especiales
            $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        
        return $data;
    }
    
    /**
     * Verifica permisos de tabla
     */
    private function checkTablePermissions($database, $table, $operation) {
        // Verificar si es tabla sensible
        if (in_array(strtolower($table), $this->config['sensitive_tables'])) {
            if ($operation !== 'SELECT') {
                $this->logSecurityEvent("Intento de modificar tabla sensible: $database.$table", 'CRITICAL');
                return false;
            }
        }
        
        // Verificar tablas permitidas
        if (!empty($this->allowedTables)) {
            $key = "$database.$table";
            if (!in_array($key, $this->allowedTables) && !in_array($table, $this->allowedTables)) {
                $this->logSecurityEvent("Intento de acceder a tabla no permitida: $database.$table", 'WARNING');
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Consulta segura con múltiples capas de protección
     */
    public function secureQuery($query, $params = [], $connectionName = null, $allowWrite = false) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        // 1. Verificar IP bloqueada
        if ($this->isIPBlocked($ip)) {
            $this->logSecurityEvent("Intento de acceso desde IP bloqueada: $ip");
            throw new Exception("Acceso denegado: IP temporalmente bloqueada");
        }
        
        // 2. Verificar tamaño de consulta
        if (strlen($query) > $this->config['max_query_length']) {
            $this->logFailedAttempt($ip, "Consulta excede longitud máxima", substr($query, 0, 200));
            throw new Exception("Consulta demasiado larga");
        }
        
        // 3. Detectar SQL Injection
        if ($this->config['enable_sql_injection_detection']) {
            $injectionDetected = $this->detectSQLInjection($query);
            if ($injectionDetected) {
                $this->logFailedAttempt($ip, $injectionDetected, $query);
                $this->logSecurityEvent($injectionDetected . " - IP: $ip", 'CRITICAL');
                throw new Exception("Consulta bloqueada por razones de seguridad");
            }
        }
        
        // 4. Verificar tipo de operación
        $queryUpper = strtoupper($query);
        $isWriteOperation = preg_match('/^\s*(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)/', $queryUpper);
        
        if ($isWriteOperation && !$allowWrite) {
            $this->logFailedAttempt($ip, "Intento de escritura no permitido", $query);
            throw new Exception("Operación de escritura no permitida en este contexto");
        }
        
        // 5. Logging de consultas
        if ($this->config['enable_query_logging']) {
            $this->logSecurityEvent("Consulta ejecutada: " . substr($query, 0, 500), 'INFO');
        }
        
        // 6. Ejecutar consulta de forma segura
        try {
            if (empty($params)) {
                $result = $this->connectionManager->query($query, $connectionName);
            } else {
                $result = $this->connectionManager->executePrepared($query, $params, $connectionName);
            }
            
            // Limpiar intentos fallidos si tiene éxito
            unset($this->failedAttempts[$ip]);
            
            return $result;
            
        } catch (Exception $e) {
            $this->logFailedAttempt($ip, "Error en consulta: " . $e->getMessage(), $query);
            throw $e;
        }
    }
    
    /**
     * Obtiene datos con protección
     */
    public function secureFetch($sql, $params = [], $connectionName = null) {
        $result = $this->secureQuery($sql, $params, $connectionName, false);
        
        if ($result instanceof mysqli_result) {
            $data = $result->fetch_all(MYSQLI_ASSOC);
            return $this->sanitizeData($data);
        }
        
        return $this->sanitizeData($result);
    }
    
    /**
     * Inserta datos con encriptación opcional
     */
    public function secureInsert($table, $data, $connectionName = null, $encryptFields = []) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        // Verificar permisos de tabla
        $dbName = $this->getCurrentDatabase($connectionName);
        if (!$this->checkTablePermissions($dbName, $table, 'INSERT')) {
            throw new Exception("No tiene permisos para insertar en esta tabla");
        }
        
        // Encriptar campos sensibles
        foreach ($encryptFields as $field) {
            if (isset($data[$field])) {
                $data[$field] = $this->encryptData($data[$field]);
            }
        }
        
        // Sanitizar datos
        $data = $this->sanitizeData($data);
        
        // Verificar XSS en datos
        foreach ($data as $key => $value) {
            $xssDetected = $this->detectXSS($value);
            if ($xssDetected) {
                $this->logFailedAttempt($ip, $xssDetected . " en campo $key", json_encode($data));
                throw new Exception("Datos bloqueados: posible XSS detectado");
            }
        }
        
        return $this->connectionManager->insert($table, $data, $connectionName);
    }
    
    /**
     * Actualiza datos con protección
     */
    public function secureUpdate($table, $data, $where, $whereParams = [], $connectionName = null) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        // Verificar permisos
        $dbName = $this->getCurrentDatabase($connectionName);
        if (!$this->checkTablePermissions($dbName, $table, 'UPDATE')) {
            throw new Exception("No tiene permisos para actualizar esta tabla");
        }
        
        // Sanitizar datos
        $data = $this->sanitizeData($data);
        
        // Verificar XSS
        foreach ($data as $key => $value) {
            $xssDetected = $this->detectXSS($value);
            if ($xssDetected) {
                $this->logFailedAttempt($ip, $xssDetected . " en campo $key", json_encode($data));
                throw new Exception("Datos bloqueados: posible XSS detectado");
            }
        }
        
        return $this->connectionManager->update($table, $data, $where, $whereParams, $connectionName);
    }
    
    /**
     * Encripta datos sensibles
     */
    public function encryptData($data) {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = openssl_encrypt($data, 'aes-256-cbc', $this->encryptionKey, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Desencripta datos
     */
    public function decryptData($encryptedData) {
        $data = base64_decode($encryptedData);
        $ivLength = openssl_cipher_iv_length('aes-256-cbc');
        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);
        return openssl_decrypt($encrypted, 'aes-256-cbc', $this->encryptionKey, 0, $iv);
    }
    
    /**
     * Obtiene base de datos actual
     */
    private function getCurrentDatabase($connectionName) {
        $conn = $this->connectionManager->getConnection($connectionName);
        $result = $conn->query("SELECT DATABASE()");
        $row = $result->fetch_row();
        return $row[0];
    }
    
    /**
     * Genera respaldo de seguridad
     */
    public function backupSensitiveData($connectionName = null) {
        $backup = [
            'timestamp' => date('Y-m-d H:i:s'),
            'blocked_ips' => $this->blockedIPs,
            'failed_attempts' => $this->failedAttempts,
            'security_log' => array_slice($this->securityLog, -100), // Últimos 100 eventos
            'encryption_key_hash' => hash('sha256', $this->encryptionKey)
        ];
        
        $backupFile = 'security_backup_' . date('Ymd_His') . '.json';
        file_put_contents($backupFile, json_encode($backup, JSON_PRETTY_PRINT));
        
        return $backupFile;
    }
    
    /**
     * Configura reglas de protección
     */
    public function setConfig($key, $value) {
        if (isset($this->config[$key])) {
            $this->config[$key] = $value;
            return true;
        }
        return false;
    }
    
    /**
     * Permite tablas específicas
     */
    public function allowTables($tables, $database = '*') {
        foreach ($tables as $table) {
            $this->allowedTables[] = ($database === '*') ? $table : "$database.$table";
        }
    }
    
    /**
     * Verifica salud del sistema
     */
    public function healthCheck() {
        return [
            'status' => 'healthy',
            'blocked_ips_count' => count($this->blockedIPs),
            'failed_attempts_count' => array_sum(array_map('count', $this->failedAttempts)),
            'encryption_enabled' => !empty($this->encryptionKey),
            'protection_level' => 'high',
            'last_backup' => file_exists('security_backup_*.json') ? 'available' : 'none'
        ];
    }
}

// ============ EJEMPLO DE USO COMPLETO ============

/*
// Configuración de conexiones múltiples
$configs = [
    'main' => [
        'host' => 'localhost',
        'user' => 'root',
        'pass' => 'password',
        'db' => 'main_db'
    ],
    'users' => [
        'host' => 'localhost',
        'user' => 'user_db',
        'pass' => 'user_pass',
        'db' => 'users_db'
    ]
];

// Inicializar gestor de conexiones
$dbManager = new MySQLConnectionManager($configs);

// Inicializar sistema de protección
$protection = new DatabaseProtectionSystem($dbManager, 'mi_clave_secreta_123');

// Configurar protección
$protection->setConfig('max_failed_attempts', 3);
$protection->setConfig('block_time_minutes', 60);
$protection->allowTables(['users', 'products'], 'main_db');

try {
    // Consulta segura
    $users = $protection->secureFetch(
        "SELECT * FROM users WHERE status = ? AND last_login > ?",
        ['active', '2024-01-01'],
        'users'
    );
    
    // Inserción segura con encriptación
    $userId = $protection->secureInsert(
        'users',
        [
            'username' => 'john_doe',
            'email' => 'john@example.com',
            'password' => 'secret123',
            'credit_card' => '4111111111111111'
        ],
        'main',
        ['credit_card'] // Campos a encriptar
    );
    
    // Actualización segura
    $affected = $protection->secureUpdate(
        'products',
        ['price' => 29.99, 'stock' => 100],
        'id = ? AND category = ?',
        [1, 'electronics'],
        'main'
    );
    
    // Respaldo de seguridad
    $backupFile = $protection->backupSensitiveData();
    
    // Verificar salud del sistema
    $health = $protection->healthCheck();
    
} catch (Exception $e) {
    echo "Error de seguridad: " . $e->getMessage();
    // Registrar en log del sistema
    error_log("Security violation: " . $e->getMessage());
}
*/

?>

// Configuración avanzada
$protection->setConfig('max_failed_attempts', 5);
$protection->setConfig('block_time_minutes', 120);
$protection->setConfig('enable_xss_protection', true);
$protection->allowTables(['users', 'orders'], 'main_db');

// adicional 
$dbManager = new MySQLConnectionManager($configs);

class MySQLConnectionManager {
    private $connections = [];
    private $configs = [];
    private $activeConnection = null;

    public function __construct($configs) {
        $this->configs = $configs;
        foreach ($configs as $name => $config) {
            $this->connections[$name] = $this->createConnection($config);
        }
    }

    private function createConnection($config) {
        $conn = new mysqli(
            $config['host'],
            $config['user'],
            $config['pass'],
            $config['db']
        );
        
        if ($conn->connect_error) {
            throw new Exception("Error de conexión: " . $conn->connect_error);
        }
        
        // Configurar charset UTF-8
        $conn->set_charset("utf8mb4");
        
        // Modo de errores estricto
        $conn->sql_mode = "STRICT_ALL_TABLES";
        
        return $conn;
    }

    public function getConnection($name = null) {
        $name = $name ?? $this->activeConnection ?? key($this->connections);
        
        if (!isset($this->connections[$name])) {
            throw new Exception("Conexión '$name' no encontrada");
        }
        
        return $this->connections[$name];
    }

    public function query($sql, $connectionName = null) {
        $conn = $this->getConnection($connectionName);
        $result = $conn->query($sql);
        
        if ($conn->error) {
            throw new Exception("Error en consulta: " . $conn->error);
        }
        
        return $result;
    }

    public function executePrepared($sql, $params, $connectionName = null) {
        $conn = $this->getConnection($connectionName);
        $stmt = $conn->prepare($sql);
        
        if (!$stmt) {
            throw new Exception("Error preparando consulta: " . $conn->error);
        }
        
        // Detectar tipos de parámetros
        $types = '';
        $bindParams = [];
        foreach ($params as $param) {
            if (is_int($param)) {
                $types .= 'i';
            } elseif (is_double($param)) {
                $types .= 'd';
            } else {
                $types .= 's';
            }
            $bindParams[] = $param;
        }
        
        if (!empty($params)) {
            $stmt->bind_param($types, ...$bindParams);
        }
        
        $stmt->execute();
        
        if ($stmt->error) {
            throw new Exception("Error ejecutando consulta: " . $stmt->error);
        }
        
        $result = $stmt->get_result();
        $stmt->close();
        
        return $result;
    }

    public function insert($table, $data, $connectionName = null) {
        $conn = $this->getConnection($connectionName);
        
        $fields = array_keys($data);
        $placeholders = array_fill(0, count($fields), '?');
        $sql = "INSERT INTO $table (" . implode(',', $fields) . ") VALUES (" . implode(',', $placeholders) . ")";
        
        $result = $this->executePrepared($sql, array_values($data), $connectionName);
        
        return $conn->insert_id;
    }

    public function update($table, $data, $where, $whereParams, $connectionName = null) {
        $conn = $this->getConnection($connectionName);
        
        $setClause = [];
        $params = [];
        foreach ($data as $field => $value) {
            $setClause[] = "$field = ?";
            $params[] = $value;
        }
        
        // Agregar parámetros WHERE
        foreach ($whereParams as $param) {
            $params[] = $param;
        }
        
        $sql = "UPDATE $table SET " . implode(', ', $setClause) . " WHERE $where";
        
        $result = $this->executePrepared($sql, $params, $connectionName);
        
        return $conn->affected_rows;
    }

    public function setActiveConnection($name) {
        if (!isset($this->connections[$name])) {
            throw new Exception("Conexión '$name' no existe");
        }
        $this->activeConnection = $name;
    }

    public function beginTransaction($connectionName = null) {
        $conn = $this->getConnection($connectionName);
        $conn->begin_transaction();
    }

    public function commit($connectionName = null) {
        $conn = $this->getConnection($connectionName);
        $conn->commit();
    }

    public function rollback($connectionName = null) {
        $conn = $this->getConnection($connectionName);
        $conn->rollback();
    }
}

class MySQLConnectionPool {
    private $pool = [];
    private $config;
    private $maxConnections = 10;
    private $minConnections = 2;
    private $connectionsInUse = 0;

    public function __construct($config, $max = 10, $min = 2) {
        $this->config = $config;
        $this->maxConnections = $max;
        $this->minConnections = $min;
        
        // Crear conexiones mínimas
        for ($i = 0; $i < $min; $i++) {
            $this->pool[] = $this->createConnection();
        }
    }

    private function createConnection() {
        $conn = new mysqli(
            $this->config['host'],
            $this->config['user'],
            $this->config['pass'],
            $this->config['db']
        );
        
        if ($conn->connect_error) {
            throw new Exception("Error en pool: " . $conn->connect_error);
        }
        
        $conn->set_charset("utf8mb4");
        return $conn;
    }

    public function getConnection() {
        if (!empty($this->pool)) {
            $this->connectionsInUse++;
            return array_pop($this->pool);
        }
        
        if ($this->connectionsInUse < $this->maxConnections) {
            $this->connectionsInUse++;
            return $this->createConnection();
        }
        
        throw new Exception("Límite de conexiones alcanzado");
    }

    public function releaseConnection($conn) {
        if (count($this->pool) < $this->minConnections) {
            $this->pool[] = $conn;
        } else {
            $conn->close();
        }
        $this->connectionsInUse--;
    }
}

class MigrationManager {
    private $connectionManager;
    private $migrationTable = 'migrations';

    public function __construct($connectionManager) {
        $this->connectionManager = $connectionManager;
        $this->ensureMigrationTable();
    }

    private function ensureMigrationTable() {
        $sql = "CREATE TABLE IF NOT EXISTS {$this->migrationTable} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            version VARCHAR(50) UNIQUE,
            description TEXT,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            executed_by VARCHAR(100)
        )";
        
        $this->connectionManager->query($sql);
    }

    public function migrate($version) {
        $migrationFile = __DIR__ . "/migrations/$version.sql";
        
        if (!file_exists($migrationFile)) {
            throw new Exception("Migración $version no encontrada");
        }

        // Verificar si ya fue ejecutada
        $check = $this->connectionManager->executePrepared(
            "SELECT id FROM {$this->migrationTable} WHERE version = ?",
            [$version]
        );
        
        if ($check->num_rows > 0) {
            throw new Exception("Migración $version ya ejecutada");
        }

        // Ejecutar migración
        $sql = file_get_contents($migrationFile);
        
        // Dividir en múltiples consultas
        $queries = array_filter(
            array_map('trim', explode(';', $sql)),
            fn($q) => !empty($q)
        );
        
        $this->connectionManager->beginTransaction();
        
        try {
            foreach ($queries as $query) {
                $this->connectionManager->query($query);
            }
            
            // Registrar migración
            $this->connectionManager->executePrepared(
                "INSERT INTO {$this->migrationTable} (version, description, executed_by) VALUES (?, ?, ?)",
                [$version, "Migration $version", $_SERVER['REMOTE_ADDR'] ?? 'cli']
            );
            
            $this->connectionManager->commit();
            
            return true;
        } catch (Exception $e) {
            $this->connectionManager->rollback();
            throw $e;
        }
    }

    public function getStatus() {
        $result = $this->connectionManager->query(
            "SELECT * FROM {$this->migrationTable} ORDER BY executed_at DESC"
        );
        
        return $result->fetch_all(MYSQLI_ASSOC);
    }
}

class QueryCache {
    private $cache = [];
    private $ttl = 300; // 5 minutos
    private $enabled = true;
    private $maxEntries = 1000;

    public function get($key) {
        if (!$this->enabled) return null;
        
        if (isset($this->cache[$key])) {
            $entry = $this->cache[$key];
            if (time() - $entry['time'] < $this->ttl) {
                return $entry['data'];
            }
            unset($this->cache[$key]);
        }
        
        return null;
    }

    public function set($key, $data) {
        if (!$this->enabled) return;
        
        // Limitar tamaño de caché
        if (count($this->cache) >= $this->maxEntries) {
            array_shift($this->cache);
        }
        
        $this->cache[$key] = [
            'data' => $data,
            'time' => time()
        ];
    }

    public function clear($pattern = null) {
        if ($pattern === null) {
            $this->cache = [];
            return;
        }
        
        foreach ($this->cache as $key => $value) {
            if (strpos($key, $pattern) !== false) {
                unset($this->cache[$key]);
            }
        }
    }
}

class DatabaseMetrics {
    private $metrics = [
        'query_count' => 0,
        'slow_queries' => [],
        'error_count' => 0,
        'avg_response_time' => 0,
        'total_response_time' => 0
    ];
    private $slowQueryThreshold = 1.0; // segundos

    public function recordQuery($query, $duration) {
        $this->metrics['query_count']++;
        $this->metrics['total_response_time'] += $duration;
        $this->metrics['avg_response_time'] = 
            $this->metrics['total_response_time'] / $this->metrics['query_count'];
        
        if ($duration > $this->slowQueryThreshold) {
            $this->metrics['slow_queries'][] = [
                'query' => $query,
                'duration' => $duration,
                'time' => date('Y-m-d H:i:s')
            ];
            
            // Limitar almacenamiento de queries lentas
            if (count($this->metrics['slow_queries']) > 100) {
                array_shift($this->metrics['slow_queries']);
            }
        }
    }

    public function recordError($error) {
        $this->metrics['error_count']++;
    }

    public function getMetrics() {
        return $this->metrics;
    }

    public function exportMetrics() {
        return json_encode($this->metrics, JSON_PRETTY_PRINT);
    }
}

// Agregar estas propiedades
private $queryCache;
private $metrics;
private $migrationManager;

// Modificar constructor
public function __construct($connectionManager, $encryptionKey = null) {
    // ... código existente ...
    $this->queryCache = new QueryCache();
    $this->metrics = new DatabaseMetrics();
    $this->migrationManager = new MigrationManager($connectionManager);
}

// Modificar secureQuery para cache y métricas
public function secureQuery($query, $params = [], $connectionName = null, $allowWrite = false) {
    // ... validaciones existentes ...
    
    // Verificar caché para SELECT
    if (strtoupper(substr(trim($query), 0, 6)) === 'SELECT') {
        $cacheKey = md5($query . json_encode($params) . $connectionName);
        $cachedResult = $this->queryCache->get($cacheKey);
        if ($cachedResult !== null) {
            return $cachedResult;
        }
    }
    
    $startTime = microtime(true);
    
    try {
        // ... ejecución existente ...
        $result = parent::secureQuery(...);
        
        $duration = microtime(true) - $startTime;
        $this->metrics->recordQuery($query, $duration);
        
        // Guardar en caché
        if (strtoupper(substr(trim($query), 0, 6)) === 'SELECT') {
            $this->queryCache->set($cacheKey, $result);
        }
        
        return $result;
        
    } catch (Exception $e) {
        $this->metrics->recordError($e->getMessage());
        throw $e;
    }
}

// Método para migraciones
public function runMigration($version) {
    return $this->migrationManager->migrate($version);
}

// Método para métricas
public function getDatabaseMetrics() {
    return $this->metrics->getMetrics();
}

// Limpiar caché
public function clearCache($pattern = null) {
    $this->queryCache->clear($pattern);
}

<?php
return [
    'connections' => [
        'main' => [
            'host' => $_ENV['DB_HOST'] ?? 'localhost',
            'user' => $_ENV['DB_USER'] ?? 'root',
            'pass' => $_ENV['DB_PASSWORD'] ?? '',
            'db' => $_ENV['DB_NAME'] ?? 'main_db',
            'charset' => 'utf8mb4',
            'pool_size' => 10
        ],
        'users' => [
            'host' => $_ENV['USERS_DB_HOST'] ?? 'localhost',
            'user' => $_ENV['USERS_DB_USER'] ?? 'user_db',
            'pass' => $_ENV['USERS_DB_PASSWORD'] ?? '',
            'db' => $_ENV['USERS_DB_NAME'] ?? 'users_db',
            'charset' => 'utf8mb4',
            'pool_size' => 5
        ]
    ],
    'cache' => [
        'enabled' => true,
        'ttl' => 300,
        'max_entries' => 1000
    ],
    'monitoring' => [
        'slow_query_threshold' => 1.0,
        'log_queries' => true,
        'log_errors' => true
    ]
];

// bootstrap.php
require_once 'DatabaseProtectionSystem.php';
require_once 'MySQLConnectionManager.php';
require_once 'MySQLConnectionPool.php';
require_once 'MigrationManager.php';
require_once 'QueryCache.php';
require_once 'DatabaseMetrics.php';

// Cargar configuración
$config = require 'config/database.php';

// Inicializar gestor de conexiones
$dbManager = new MySQLConnectionManager($config['connections']);

// Inicializar sistema de protección
$protection = new DatabaseProtectionSystem(
    $dbManager,
    $_ENV['ENCRYPTION_KEY'] ?? null
);

// Configuración avanzada
$protection->setConfig('max_failed_attempts', 5);
$protection->setConfig('block_time_minutes', 120);
$protection->setConfig('enable_xss_protection', true);
$protection->allowTables(['users', 'orders', 'products'], 'main_db');

// Ejecutar migraciones
$protection->runMigration('20240101000000_create_users_table');

// Usar el sistema
try {
    // Con caché automático
    $users = $protection->secureFetch(
        "SELECT * FROM users WHERE status = ?",
        ['active'],
        'users'
    );
    
    // Ver métricas
    $metrics = $protection->getDatabaseMetrics();
    
} catch (Exception $e) {
    error_log($e->getMessage());
}