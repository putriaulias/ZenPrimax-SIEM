<?php
// Fungsi bersama: database, login, log, rule, dan blokir.
declare(strict_types=1);
date_default_timezone_set('Asia/Jakarta');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name('ZENPRIMAX_SIEM');
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure' => !empty($_SERVER['HTTPS'])
            && $_SERVER['HTTPS'] !== 'off',
    ]);
    session_start();
}

function cfg(): array
{
    static $config = null;
    return $config ??= require __DIR__ . '/config.php';
}

function connect_db(string $name): PDO
{
    static $dbs = [];
    if (isset($dbs[$name])) {
        return $dbs[$name];
    }
    $c = cfg();
    $database = $c[$name];
    $dsn = 'mysql:host=' . $c['db_host'];
    $dsn .= ';port=' . $c['db_port'];
    $dsn .= ';dbname=' . $database . ';charset=utf8mb4';
    $dbs[$name] = new PDO(
        $dsn,
        $c['db_user'],
        $c['db_pass'],
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
    $dbs[$name]->exec("SET time_zone = '+00:00'");
    return $dbs[$name];
}

function remote_mode(): bool
{
    return trim((string) (cfg()['remote_api_url'] ?? '')) !== '';
}

function siem(): PDO
{
    return connect_db('siem_db');
}

function lab(): PDO
{
    return connect_db('lab_db');
}

function html(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function signed_in(): bool
{
    return !empty($_SESSION['siem_user']);
}

function need_login(): void
{
    if (!signed_in()) {
        header('Location: index.php?page=login');
        exit;
    }
}

function csrf(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(20));
    }
    return $_SESSION['csrf'];
}

function csrf_input(): string
{
    return '<input type="hidden" name="csrf" value="'
        . html(csrf()) . '">';
}

function verify_post(): void
{
    $value = $_POST['csrf'] ?? null;
    if (!is_string($value) || !hash_equals(csrf(), $value)) {
        http_response_code(403);
        exit('Sesi tidak valid. Refresh halaman lalu coba lagi.');
    }
}

function redirect(string $page, string $message = ''): never
{
    $url = 'index.php?page=' . rawurlencode($page);
    if ($message !== '') {
        $url .= '&notice=' . rawurlencode($message);
    }
    header('Location: ' . $url, true, 303);
    exit;
}

function query_all(PDO $db, string $sql, array $values = []): array
{
    $q = $db->prepare($sql);
    $q->execute($values);
    return $q->fetchAll();
}

function query_one(PDO $db, string $sql, array $values = []): ?array
{
    $q = $db->prepare($sql);
    $q->execute($values);
    return $q->fetch() ?: null;
}

function country_for(string $ip): string
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return 'Tidak diketahui';
    }
    if (!filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    )) {
        return 'Lokal / Privat / Simulasi';
    }
    $db = siem();
    $row = query_one(
        $db,
        'SELECT country FROM geo_cache WHERE ip = ?',
        [$ip]
    );
    if ($row) {
        return $row['country'];
    }
    if (!cfg()['geo_enabled'] || !function_exists('curl_init')) {
        return 'Belum diperiksa';
    }

    // Hanya memanggil alamat URL layanan yang sudah ditentukan,
    // tidak menerima URL dari pengunjung atau parameter user.
    $curl = curl_init(cfg()['geo_url'] . rawurlencode($ip));
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 3,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_FOLLOWLOCATION => false,
    ]);
    $body = curl_exec($curl);
    $code = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);
    $data = $code === 200 && is_string($body)
        ? json_decode($body, true)
        : null;
    $country = is_array($data) && ($data['success'] ?? false)
        ? substr((string) ($data['country'] ?? ''), 0, 100)
        : 'Tidak diketahui';
    if ($country === '') {
        $country = 'Tidak diketahui';
    }
    $q = $db->prepare(
        'INSERT INTO geo_cache (ip, country) VALUES (?, ?) '
        . 'ON DUPLICATE KEY UPDATE country = VALUES(country)'
    );
    $q->execute([$ip, $country]);
    return $country;
}

function add_log(
    string $source,
    int $sourceId,
    string $type,
    string $ip,
    string $user,
    int $time,
    array $data = [],
    bool $allowBlock = true
): ?int {
    $q = siem()->prepare(
        'INSERT IGNORE INTO logs '
        . '(source, source_id, event_type, ip, actor, country, '
        . 'event_time, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );
    $q->execute([
        $source,
        $sourceId,
        $type,
        $ip,
        $user,
        country_for($ip),
        $time,
        json_encode($data, JSON_UNESCAPED_UNICODE),
    ]);
    $id = (int) siem()->lastInsertId();
    if ($q->rowCount() === 0 || $id === 0) {
        return null;
    }
    detect($id, $type, $ip, $time, $allowBlock);
    return $id;
}

function detect(int $logId, string $type, string $ip, int $time, bool $allowBlock = true): void
{
    $rules = query_all(
        siem(),
        'SELECT * FROM rules WHERE enabled = 1 AND event_type = ?',
        [$type]
    );
    foreach ($rules as $rule) {
        $start = $time - (int) $rule['window_seconds'];
        $q = query_one(
            siem(),
            'SELECT COUNT(*) AS total FROM logs '
            . 'WHERE event_type = ? AND ip = ? '
            . 'AND event_time BETWEEN ? AND ?',
            [$type, $ip, $start, $time]
        );
        $total = (int) ($q['total'] ?? 0);
        if ($total < (int) $rule['threshold_count']) {
            continue;
        }

        // Satu alert untuk satu rule, sumber dan time window.
        // Jangan membuat alert baru ketika threshold masih terlampaui.
        $last = query_one(
            siem(),
            'SELECT id FROM alerts WHERE rule_id = ? AND ip = ? '
            . 'AND last_event_time >= ? ORDER BY id DESC LIMIT 1',
            [(int) $rule['id'], $ip, $start]
        );
        if ($last) {
            continue;
        }

        $summary = (string) $rule['name'] . ': ' . $total
            . ' event dari ' . $ip;
        $q = siem()->prepare(
            'INSERT INTO alerts (rule_id, log_id, ip, severity, '
            . 'title, details, recommendation, event_count, '
            . 'last_event_time, created_at) '
            . 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())'
        );
        $q->execute([
            (int) $rule['id'], $logId, $ip,
            $rule['severity'], $rule['name'], $summary,
            $rule['recommendation'], $total, $time,
        ]);
        $alertId = (int) siem()->lastInsertId();
        // Jangan blokir berdasarkan log historis lama yang baru diimpor.
        if (
            $allowBlock
            && (!remote_mode() || ($type === 'LOGIN_FAILURE' && mitigation_ready()))
            && (int) $rule['auto_block'] === 1
            && abs(time() - $time) <= 120
        ) {
            block_ip($ip, $alertId, 'Auto: ' . $rule['name']);
        }
    }
}

function mitigation_ready(): bool
{
    return remote_mode()
        && str_starts_with((string) (cfg()['remote_mitigation_url'] ?? ''), 'https://')
        && strlen((string) (cfg()['remote_mitigation_token'] ?? '')) >= 48;
}

function remote_mitigation(string $action, array $data = []): array
{
    if (!mitigation_ready()) {
        throw new RuntimeException('Remote Mitigation API belum diatur.');
    }
    if (!function_exists('curl_init')) {
        throw new RuntimeException('Ekstensi cURL belum aktif.');
    }
    $url = (string) cfg()['remote_mitigation_url'];
    $curl = curl_init($url);
    $headers = [
        'X-SIEM-Mitigation-Token: ' . cfg()['remote_mitigation_token'],
        'Accept: application/json',
    ];
    if ($action !== 'list') {
        $headers[] = 'Content-Type: application/json';
    }
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_FOLLOWLOCATION => false,
    ]);
    if ($action !== 'list') {
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode(
            ['action' => $action] + $data, JSON_UNESCAPED_UNICODE
        ));
    }
    $body = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);
    $answer = is_string($body) ? json_decode($body, true) : null;
    if ($status !== 200 || !is_array($answer) || !($answer['ok'] ?? false)) {
        $message = is_array($answer) ? (string) ($answer['error'] ?? '') : '';
        throw new RuntimeException('Mitigasi Hostinger gagal (HTTP '
            . $status . '). ' . substr($message, 0, 120));
    }
    return $answer;
}

function update_expired(): void
{
    if (remote_mode()) {
        return;
    }
    lab()->exec("UPDATE siem_blocks SET status = 'Expired' "
        . "WHERE status = 'Active' AND expires_at <= UTC_TIMESTAMP()");
}

function block_ip(string $ip, ?int $alertId, string $reason): void
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        throw new RuntimeException('IP tidak valid.');
    }
    if (remote_mode()) {
        if (!filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            throw new RuntimeException('Mode Hostinger hanya mengizinkan IP publik.');
        }
        remote_mitigation('block', [
            'ip' => $ip, 'alert_id' => $alertId,
            'reason' => substr($reason, 0, 255),
        ]);
        return;
    }
    update_expired();
    $db = lab();
    $db->beginTransaction();
    try {
        $row = query_one($db,
            "SELECT id FROM siem_blocks WHERE ip = ? "
            . "AND status = 'Active' ORDER BY id DESC LIMIT 1 FOR UPDATE",
            [$ip]);
        if (!$row) {
            $hours = min(24, max(1, (int) cfg()['block_hours']));
            $q = $db->prepare('INSERT INTO siem_blocks '
                . '(ip, status, reason, alert_id, created_at, expires_at) '
                . "VALUES (?, 'Active', ?, ?, UTC_TIMESTAMP(), "
                . "DATE_ADD(UTC_TIMESTAMP(), INTERVAL $hours HOUR))");
            $q->execute([$ip, substr($reason, 0, 255), $alertId]);
        }
        $db->commit();
    } catch (Throwable $error) {
        $db->rollBack();
        throw $error;
    }
}

function unblock_ip(int $id): void
{
    if ($id < 1) {
        throw new RuntimeException('ID blokir tidak valid.');
    }
    if (remote_mode()) {
        remote_mitigation('unblock', ['block_id' => $id]);
        return;
    }
    update_expired();
    $q = lab()->prepare("UPDATE siem_blocks SET status = 'Released', "
        . 'released_at = UTC_TIMESTAMP() '
        . "WHERE id = ? AND status = 'Active'");
    $q->execute([$id]);
}

function get_blocks(): array
{
    if (remote_mode()) {
        if (!mitigation_ready()) {
            return [];
        }
        $result = remote_mitigation('list');
        return is_array($result['blocks'] ?? null) ? $result['blocks'] : [];
    }
    update_expired();
    return query_all(lab(),
        'SELECT * FROM siem_blocks ORDER BY id DESC LIMIT 150');
}

function count_rows(string $table): int
{
    $tables = ['logs', 'alerts', 'rules'];
    if (!in_array($table, $tables, true)) {
        return 0;
    }
    return (int) siem()->query(
        'SELECT COUNT(*) FROM ' . $table
    )->fetchColumn();
}
