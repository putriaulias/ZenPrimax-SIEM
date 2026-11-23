<?php
// Membuat database SIEM dan menambah tabel blokir di database lab.
declare(strict_types=1);
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Jalankan dari terminal VS Code.');
}
$c = require __DIR__ . '/config.php';
foreach (['siem_db', 'lab_db'] as $key) {
    if (!preg_match('/^[A-Za-z0-9_]+$/', $c[$key])) {
        exit('Nama database tidak valid.' . PHP_EOL);
    }
}
try {
    $dsn = 'mysql:host=' . $c['db_host']
        . ';port=' . $c['db_port'] . ';charset=utf8mb4';
    $db = new PDO($dsn, $c['db_user'], $c['db_pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $name = $c['siem_db'];
    $db->exec("CREATE DATABASE IF NOT EXISTS `$name` "
        . 'CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    $db->exec("USE `$name`");
    $schema = [
        'CREATE TABLE IF NOT EXISTS admins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL
        ) ENGINE=InnoDB',
        'CREATE TABLE IF NOT EXISTS logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            source VARCHAR(20) NOT NULL,
            source_id BIGINT NOT NULL,
            event_type VARCHAR(80) NOT NULL,
            ip VARCHAR(45) NOT NULL,
            actor VARCHAR(80) NOT NULL,
            country VARCHAR(100) NOT NULL,
            event_time BIGINT NOT NULL,
            details_json TEXT,
            UNIQUE KEY unique_event (source, source_id),
            INDEX lookup_event (event_type, ip, event_time),
            INDEX lookup_time (event_time)
        ) ENGINE=InnoDB',
        'CREATE TABLE IF NOT EXISTS rules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            rule_key VARCHAR(80) NOT NULL UNIQUE,
            name VARCHAR(100) NOT NULL,
            event_type VARCHAR(80) NOT NULL,
            severity VARCHAR(10) NOT NULL,
            threshold_count INT NOT NULL,
            window_seconds INT NOT NULL,
            auto_block TINYINT NOT NULL DEFAULT 0,
            enabled TINYINT NOT NULL DEFAULT 1,
            recommendation TEXT NOT NULL
        ) ENGINE=InnoDB',
        'CREATE TABLE IF NOT EXISTS alerts (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            rule_id INT NOT NULL,
            log_id BIGINT NOT NULL,
            ip VARCHAR(45) NOT NULL,
            severity VARCHAR(10) NOT NULL,
            title VARCHAR(100) NOT NULL,
            details TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            event_count INT NOT NULL,
            last_event_time BIGINT NOT NULL,
            created_at DATETIME NOT NULL,
            INDEX alert_lookup (rule_id, ip, last_event_time)
        ) ENGINE=InnoDB',
        'CREATE TABLE IF NOT EXISTS cursors (
            name VARCHAR(80) PRIMARY KEY,
            value VARCHAR(200) NOT NULL
        ) ENGINE=InnoDB',
        'CREATE TABLE IF NOT EXISTS geo_cache (
            ip VARCHAR(45) PRIMARY KEY,
            country VARCHAR(100) NOT NULL,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB',
    ];
    foreach ($schema as $sql) {
        $db->exec($sql);
    }
    $lab = $c['lab_db'];
    $q = $db->query('SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA '
        . "WHERE SCHEMA_NAME = " . $db->quote($lab));
    if (!$q->fetch()) {
        throw new RuntimeException(
            'Database lab tidak ditemukan: ' . $lab . '. Instal website premium dahulu.'
        );
    }
    $db->exec("USE `$lab`");
    $db->exec('CREATE TABLE IF NOT EXISTS siem_blocks (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        status ENUM("Active", "Expired", "Released") NOT NULL,
        reason VARCHAR(255) NOT NULL,
        alert_id BIGINT DEFAULT NULL,
        created_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        released_at DATETIME DEFAULT NULL,
        INDEX ip_status (ip, status)
    ) ENGINE=InnoDB');
    $db->exec("USE `$name`");

    $rules = [
        ['login', 'Login gagal berulang', 'LOGIN_FAILURE', 'High', 5, 180, 1,
            'Periksa akun dan IP asal. Blokir sementara sumber, konfirmasi log, '
            . 'dan lakukan reset kredensial jika diperlukan.'],
        ['request', 'Lonjakan request HTTP', 'HTTP_REQUEST', 'High', 30, 60, 0,
            'Periksa rate, pola URL dan IP. Terapkan pembatasan akses '
            . 'sementara jika terbukti menyalahgunakan layanan.'],
        ['http5xx', 'Error HTTP 5xx berulang', 'HTTP_5XX', 'Medium', 3, 300, 0,
            'Periksa error.log Apache, endpoint gagal dan kesehatan server. '
            . 'Hindari memblokir IP hanya karena server error.'],
        ['payment_timeout', 'Checkout melebihi 3 menit',
            'PAYMENT_DURATION_EXCEEDED', 'Medium', 1, 60, 0,
            'Verifikasi status melalui Midtrans Sandbox, cek Order ID, '
            . 'dan investigasi bila terjadi berulang. Jangan auto-block.'],
        ['payment_failed', 'Pembayaran gagal berulang',
            'PAYMENT_FAILED', 'Medium', 3, 600, 0,
            'Periksa metode dan status pembayaran Midtrans. '
            . 'Jangan menyimpulkan fraud dari kegagalan saja.'],
        ['product', 'Perubahan produk', 'PRODUCT_UPDATED', 'Low', 1, 60, 0,
            'Audit admin, catat perubahan harga dan cocokkan dengan persetujuan.'],
    ];
    $q = $db->prepare(
        'INSERT IGNORE INTO rules '
        . '(rule_key, name, event_type, severity, threshold_count, '
        . 'window_seconds, auto_block, recommendation) '
        . 'VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );
    foreach ($rules as $rule) {
        $q->execute($rule);
    }

    $count = (int) $db->query('SELECT COUNT(*) FROM admins')->fetchColumn();
    if ($count === 0) {
        $pass = bin2hex(random_bytes(9));
        $q = $db->prepare(
            'INSERT INTO admins (username, password_hash) VALUES (?, ?)'
        );
        $q->execute(['admin', password_hash($pass, PASSWORD_DEFAULT)]);
        echo "[ADMIN BARU] username: admin | password: $pass\n";
        echo "Simpan password ini. Tidak dicetak ulang.\n";
    }
    echo "[OK] SIEM database dan tabel blokir siap.\n";
    echo "[OK] 6 aturan deteksi telah disiapkan.\n";
} catch (Throwable $error) {
    fwrite(STDERR, '[ERROR] ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
