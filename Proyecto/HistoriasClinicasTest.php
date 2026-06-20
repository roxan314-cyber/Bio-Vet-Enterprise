<?php

use PHPUnit\Framework\TestCase;

class HistoriasClinicasTest extends TestCase
{
    private PDO $db;

    /**
     * Set up the database connection and schema before each test.
     */
    protected function setUp(): void
    {
        // 1. Configure your testing database credentials here
        $dsn = 'mysql:host=127.0.0.1;dbname=veterinaria_test_db;charset=utf8';
        $user = 'root';
        $password = '';

        try {
            $this->db = new PDO($dsn, $user, $password);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            $this->markTestSkipped('Database connection failed: ' . $e->getMessage());
        }

        // 2. Drop existing tables to ensure a clean state
        $this->db->exec("DROP TABLE IF EXISTS Historias_Clinicas");
        $this->db->exec("DROP TABLE IF EXISTS Clientes");
        $this->db->exec("DROP TABLE IF EXISTS Pacientes");
        $this->db->exec("DROP TABLE IF EXISTS Doctores");

        // 3. Create prerequisite tables to satisfy Foreign Keys
        $this->db->exec("CREATE TABLE Clientes (id_cliente VARCHAR(10) PRIMARY KEY)");
        $this->db->exec("CREATE TABLE Pacientes (id_paciente VARCHAR(10) PRIMARY KEY)");
        $this->db->exec("CREATE TABLE Doctores (id_doctor VARCHAR(10) PRIMARY KEY)");

        // 4. Execute your provided SQL to create the target table
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
     * Clean up after each test to prevent data leakage.
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
     * Test: Verify that the table is created with all the expected columns.
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
            $this->assertContains($column, $columns, "The table is missing the required column: {$column}");
        }
    }

    /**
     * Test: Verify that records can be inserted and data maps correctly.
     */
    public function testCanInsertAndRetrieveRecord(): void
    {
        // 1. Insert dummy data into the parent tables to satisfy foreign key constraints
        $this->db->exec("INSERT INTO Clientes (id_cliente) VALUES ('CLI-001')");
        $this->db->exec("INSERT INTO Pacientes (id_paciente) VALUES ('PAC-001')");
        $this->db->exec("INSERT INTO Doctores (id_doctor) VALUES ('DOC-001')");

        // 2. Prepare and execute the insert for Historias_Clinicas
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

        // 3. Assert the insertion was successful
        $this->assertTrue($inserted, "Failed to insert the record into Historias_Clinicas.");

        // 4. Check if AUTO_INCREMENT is working
        $lastId = $this->db->lastInsertId();
        $this->assertGreaterThan(0, $lastId, "The id_consulta AUTO_INCREMENT failed.");

        // 5. Retrieve the inserted record and verify the data matches
        $stmt = $this->db->query("SELECT * FROM Historias_Clinicas WHERE id_consulta = " . $lastId);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        $this->assertEquals('2026-06-20', $record['fecha']);
        $this->assertEquals('PAC-001', $record['id_paciente']);
        $this->assertEquals(2, $record['condicion_corporal']);
    }
}