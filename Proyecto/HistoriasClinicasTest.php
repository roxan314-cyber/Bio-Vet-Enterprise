<?php

use PHPUnit\Framework\TestCase;

class HistoriasClinicasTest extends TestCase
{
    private PDO $db;

    /**
     * Configura la conexión a la base de datos y el esquema antes de cada prueba.
     */
    protected function setUp(): void
    {
        // 1. Configura aquí las credenciales de la base de datos de pruebas
        $dsn = 'mysql:host=127.0.0.1;dbname=veterinaria_test_db;charset=utf8';
        $user = 'root';
        $password = '';

        try {
            $this->db = new PDO($dsn, $user, $password);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            $this->markTestSkipped('Conexión a la base de datos fallida: ' . $e->getMessage());
        }

        // 2. Elimina las tablas existentes para asegurar un estado limpio
        $this->db->exec("DROP TABLE IF EXISTS Historias_Clinicas");
        $this->db->exec("DROP TABLE IF EXISTS Clientes");
        $this->db->exec("DROP TABLE IF EXISTS Pacientes");
        $this->db->exec("DROP TABLE IF EXISTS Doctores");

        // 3. Crea tablas de prerrequisitos para satisfacer las llaves foráneas
        $this->db->exec("CREATE TABLE Clientes (id_cliente VARCHAR(10) PRIMARY KEY)");
        $this->db->exec("CREATE TABLE Pacientes (id_paciente VARCHAR(10) PRIMARY KEY)");
        $this->db->exec("CREATE TABLE Doctores (id_doctor VARCHAR(10) PRIMARY KEY)");

        // 4. Ejecuta el SQL proporcionado para crear la tabla Historias_Clinicas
        $sql = "
            CREATE TABLE Historias_Clinicas (
                id_consulta INT AUTO_INCREMENT PRIMARY KEY,
                fecha DATE NOT NULL,
                id_cliente VARCHAR(10),
                id_paciente VARCHAR(10),
                id_doctor VARCHAR(10),
                motivo_consulta TEXT, 
                condicion_corporal INT,
                diagnostico_dx TEXT,
                plan_accion TEXT,
                FOREIGN KEY (id_cliente) REFERENCES Clientes(id_cliente),
                FOREIGN KEY (id_paciente) REFERENCES Pacientes(id_paciente),
                FOREIGN KEY (id_doctor) REFERENCES Doctores(id_doctor)
            );
        ";
        $this->db->exec($sql);
    }

    /**
     * Limpia después de cada prueba para evitar la persistencia de datos.
     */
    protected function tearDown(): void
    {
        if (isset($this->db)) {
            $this->db->exec("DROP TABLE IF EXISTS Historias_Clinicas");
            $this->db->exec("DROP TABLE IF EXISTS Clientes");
            $this->db->exec("DROP TABLE IF EXISTS Pacientes");
            $this->db->exec("DROP TABLE IF EXISTS Doctores");
        }
    }

    /**
     * Prueba: Verifica que la tabla se cree con todas las columnas esperadas.
     */
    public function testTableExistsAndHasExpectedColumns(): void
    {
        $stmt = $this->db->query("DESCRIBE Historias_Clinicas");
        $columns = $stmt->fetchAll(PDO::FETCH_COLUMN);

        $expectedColumns = [
            'id_consulta', 'fecha', 'id_cliente', 'id_paciente', 
            'id_doctor', 'motivo_consulta', 'condicion_corporal', 
            'diagnostico_dx', 'plan_accion'
        ];

        foreach ($expectedColumns as $column) {
            $this->assertContains($column, $columns, "A la tabla le falta la columna requerida: {$column}");
        }
    }

    /**
     * Prueba: Verifica que los registros se pueden insertar y los datos se asignan correctamente.
     */
    public function testCanInsertAndRetrieveRecord(): void
    {
        // 1. Inserta datos de prueba en las tablas padre para satisfacer las llaves foráneas
        $this->db->exec("INSERT INTO Clientes (id_cliente) VALUES ('CLI-001')");
        $this->db->exec("INSERT INTO Pacientes (id_paciente) VALUES ('PAC-001')");
        $this->db->exec("INSERT INTO Doctores (id_doctor) VALUES ('DOC-001')");

        // 2. Prepara y ejecuta la inserción en Historias_Clinicas
        $stmt = $this->db->prepare("
            INSERT INTO Historias_Clinicas 
            (fecha, id_cliente, id_paciente, id_doctor, motivo_consulta, condicion_corporal, diagnostico_dx, plan_accion) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");

        $inserted = $stmt->execute([
            '2026-06-20',
            'CLI-001',
            'PAC-001',
            'DOC-001',
            'El perro no quiere comer desde hace 2 días',
            2,
            'Gastroenteritis presuntiva',
            'Administrar suero y dieta blanda'
        ]);

        // 3. Afirma que la inserción fue exitosa
        $this->assertTrue($inserted, "Falló la inserción del registro en Historias_Clinicas.");

        // 4. Verifica que el AUTO_INCREMENT está funcionando
        $lastId = $this->db->lastInsertId();
        $this->assertGreaterThan(0, $lastId, "El AUTO_INCREMENT de id_consulta falló.");

        // 5. Recupera el registro insertado y verifica que los datos coincidan
        $stmt = $this->db->query("SELECT * FROM Historias_Clinicas WHERE id_consulta = " . $lastId);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertEquals('2026-06-20', $record['fecha']);
        $this->assertEquals('PAC-001', $record['id_paciente']);
        $this->assertEquals(2, $record['condicion_corporal']);
    }
}
