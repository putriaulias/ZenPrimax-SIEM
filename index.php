<?php
// Controller SIEM: autentikasi, aksi, data halaman, dan routing.
require_once __DIR__ . '/common.php';
require_once __DIR__ . '/csv_import.php';
define('ZENPRIMAX_PAGE_CONTEXT', true);

$page = (string) ($_GET['page'] ?? 'dashboard');
$allowed = ['dashboard', 'audit', 'logs', 'blocks', 'rules', 'login'];
if (!in_array($page, $allowed, true)) {
    $page = 'dashboard';
}
$error = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    verify_post();
    $action = (string) ($_POST['action'] ?? '');
    try {
        if ($action === 'login') {
            $username = trim((string) ($_POST['username'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $user = query_one(
                siem(),
                'SELECT * FROM admins WHERE username = ?',
                [$username]
            );
            if (!$user || !password_verify(
                $password,
                $user['password_hash']
            )) {
                throw new RuntimeException('Username atau password salah.');
            }
            session_regenerate_id(true);
            $_SESSION['siem_user'] = $username;
            redirect('dashboard');
        }
        need_login();
        if ($action === 'logout') {
            $_SESSION = [];
            session_regenerate_id(true);
            redirect('login');
        }
        if ($action === 'block') {
            if (remote_mode() && !mitigation_ready()) {
                throw new RuntimeException('Remote Mitigation API belum dikonfigurasi.');
            }
            $ip = trim((string) ($_POST['ip'] ?? ''));
            $alertId = filter_var(
                $_POST['alert_id'] ?? '', FILTER_VALIDATE_INT
            );
            if ($alertId) {
                $alert = query_one(
                    siem(), 'SELECT ip FROM alerts WHERE id = ?',
                    [$alertId]
                );
                if (!$alert || $alert['ip'] !== $ip) {
                    throw new RuntimeException('Sumber alert tidak cocok.');
                }
            }
            block_ip($ip, $alertId ?: null, 'Blokir manual oleh admin SIEM');
            redirect($page, 'IP diblokir maksimal 24 jam.');
        }
        if ($action === 'unblock') {
            if (remote_mode() && !mitigation_ready()) {
                throw new RuntimeException('Remote Mitigation API belum dikonfigurasi.');
            }
            unblock_ip((int) ($_POST['block_id'] ?? 0));
            redirect($page, 'Blokir dilepas oleh admin.');
        }
        if ($action === 'rule') {
            $id = (int) ($_POST['rule_id'] ?? 0);
            $enabled = isset($_POST['enabled']) ? 1 : 0;
            $ruleRow = query_one(siem(), 'SELECT event_type FROM rules WHERE id = ?', [$id]);
            $autoAllowed = !remote_mode() || (mitigation_ready()
                && ($ruleRow['event_type'] ?? '') === 'LOGIN_FAILURE');
            $auto = isset($_POST['auto_block']) && $autoAllowed ? 1 : 0;
            $q = siem()->prepare(
                'UPDATE rules SET enabled = ?, auto_block = ? WHERE id = ?'
            );
            $q->execute([$enabled, $auto, $id]);
            redirect('rules', 'Aturan diperbarui.');
        }
        if ($action === 'create_rule') {
            $name = trim((string) ($_POST['name'] ?? ''));
            $eventType = trim((string) ($_POST['event_type'] ?? ''));
            $severity = (string) ($_POST['severity'] ?? '');
            $threshold = filter_var(
                $_POST['threshold_count'] ?? null,
                FILTER_VALIDATE_INT
            );
            $windowMinutes = filter_var(
                $_POST['window_minutes'] ?? null,
                FILTER_VALIDATE_INT
            );
            $recommendation = trim(
                (string) ($_POST['recommendation'] ?? '')
            );

            if ($name === '' || strlen($name) > 100) {
                throw new RuntimeException(
                    'Nama aturan wajib diisi (maksimal 100 karakter).'
                );
            }
            if (!preg_match('/^[A-Za-z0-9_.:-]{1,80}$/', $eventType)) {
                throw new RuntimeException(
                    'Jenis event wajib 1-80 karakter: huruf, angka, titik, '
                    . 'garis bawah, titik dua, atau tanda hubung.'
                );
            }
            if (!in_array($severity, ['High', 'Medium', 'Low'], true)) {
                throw new RuntimeException('Severity aturan tidak valid.');
            }
            if ($threshold === false || $threshold < 1 || $threshold > 1000000) {
                throw new RuntimeException(
                    'Threshold harus antara 1 dan 1.000.000 event.'
                );
            }
            if (
                $windowMinutes === false
                || $windowMinutes < 1
                || $windowMinutes > 43200
            ) {
                throw new RuntimeException(
                    'Rentang waktu harus antara 1 menit dan 30 hari.'
                );
            }
            if ($recommendation === '' || strlen($recommendation) > 60000) {
                throw new RuntimeException(
                    'Rekomendasi wajib diisi (maksimal 60.000 karakter).'
                );
            }

            $q = siem()->prepare(
                'INSERT INTO rules '
                . '(rule_key, name, event_type, severity, threshold_count, '
                . 'window_seconds, auto_block, enabled, recommendation) '
                . 'VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)'
            );
            $q->execute([
                'custom_' . bin2hex(random_bytes(12)),
                $name,
                $eventType,
                $severity,
                $threshold,
                $windowMinutes * 60,
                isset($_POST['auto_block']) && (!remote_mode() ||
                    (mitigation_ready() && $eventType === 'LOGIN_FAILURE')) ? 1 : 0,
                $recommendation,
            ]);
            redirect('rules', 'Aturan baru berhasil dibuat.');
        }
        if ($action === 'import_csv') {
            $result = import_log_csv_files($_FILES['csv_files'] ?? []);
            redirect(
                'logs',
                'Import selesai: ' . $result['imported'] . ' event baru, '
                . $result['duplicates'] . ' duplikat dilewati.'
            );
        }
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

if (!signed_in() && $page !== 'login') {
    redirect('login');
}
if (signed_in() && $page === 'login') {
    redirect('dashboard');
}

if (signed_in() && ($_GET['api'] ?? '') === 'poll') {
    require_once __DIR__ . '/worker.php';
    header('Content-Type: application/json; charset=utf-8');
    try {
        $now = time();
        $range = (string) ($_GET['range'] ?? '24h');
        if (!in_array($range, ['24h', '7d', '30d', 'custom'], true)) {
            $range = '24h';
        }

        if ($range === 'custom') {
            $startValue = is_string($_GET['start'] ?? null)
                ? $_GET['start'] : '';
            $endValue = is_string($_GET['end'] ?? null)
                ? $_GET['end'] : '';
            $zone = new DateTimeZone('Asia/Jakarta');
            $startDate = DateTimeImmutable::createFromFormat(
                '!Y-m-d', $startValue, $zone
            );
            $startErrors = DateTimeImmutable::getLastErrors();
            $endDate = DateTimeImmutable::createFromFormat(
                '!Y-m-d', $endValue, $zone
            );
            $endErrors = DateTimeImmutable::getLastErrors();
            $validStart = $startDate
                && ($startErrors === false
                    || ($startErrors['warning_count'] === 0
                        && $startErrors['error_count'] === 0))
                && $startDate->format('Y-m-d') === $startValue;
            $validEnd = $endDate
                && ($endErrors === false
                    || ($endErrors['warning_count'] === 0
                        && $endErrors['error_count'] === 0))
                && $endDate->format('Y-m-d') === $endValue;
            $dayCount = $validStart && $validEnd
                ? (int) $startDate->diff($endDate)->format('%r%a') + 1
                : 0;
            if (!$validStart || !$validEnd || $dayCount < 1
                || $dayCount > 365 || $endValue > date('Y-m-d')) {
                http_response_code(400);
                echo json_encode([
                    'ok' => false,
                    'error' => 'Pilih rentang tanggal valid maksimal 365 hari '
                        . 'dan tidak melewati hari ini.',
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }
            $bucketSeconds = 86400;
            $bucketCount = $dayCount;
            $start = $startDate->getTimestamp();
            $end = $endDate->modify('+1 day')->getTimestamp() - 1;
            $labelFormat = 'd M';
        } elseif ($range === '24h') {
            $bucketSeconds = 300;
            $bucketCount = 289;
            $start = (int) (
                floor(($now - (24 * 3600)) / $bucketSeconds)
                * $bucketSeconds
            );
            $end = $now;
            $labelFormat = 'H:i';
        } elseif ($range === '7d') {
            $bucketSeconds = 86400;
            $bucketCount = 7;
            $start = (int) (
                floor($now / $bucketSeconds) * $bucketSeconds
                - (6 * $bucketSeconds)
            );
            $end = $now;
            $labelFormat = 'd M';
        } else {
            $bucketSeconds = 86400;
            $bucketCount = 30;
            $start = (int) (
                floor($now / $bucketSeconds) * $bucketSeconds
                - (29 * $bucketSeconds)
            );
            $end = $now;
            $labelFormat = 'd M';
        }

        $sync = run_collect();
        $trend = [];
        $firstBucket = (int) (floor($start / $bucketSeconds) * $bucketSeconds);
        for ($i = 0; $i < $bucketCount; $i++) {
            $bucket = $firstBucket + ($i * $bucketSeconds);
            $trend[$bucket] = 0;
        }

        $trendSql = 'SELECT FLOOR(event_time / ' . $bucketSeconds . ') * '
            . $bucketSeconds . ' AS bucket, COUNT(*) AS total '
            . 'FROM logs WHERE event_time >= ?';
        $trendValues = [$start];
        if ($range === 'custom') {
            $trendSql .= ' AND event_time <= ?';
            $trendValues[] = $end;
        }
        $trendSql .= ' GROUP BY FLOOR(event_time / ' . $bucketSeconds . ') * '
            . $bucketSeconds;
        $rows = query_all(siem(), $trendSql, $trendValues);
        foreach ($rows as $row) {
            $bucket = (int) $row['bucket'];
            if (isset($trend[$bucket])) {
                $trend[$bucket] = (int) $row['total'];
            }
        }
        echo json_encode([
            'ok' => true,
            'sync' => $sync,
            'total_logs' => count_rows('logs'),
            'total_alerts' => count_rows('alerts'),
            'active_blocks' => count(array_filter(
                get_blocks(), fn ($r) => $r['status'] === 'Active'
            )),
            'labels' => array_map(
                fn ($t) => date($labelFormat, (int) $t), array_keys($trend)
            ),
            'values' => array_values($trend),
            'range' => $range,
            'latest' => query_all(
                siem(),
                'SELECT id, severity, title, ip FROM alerts '
                . 'ORDER BY id DESC LIMIT 5'
            ),
        ], JSON_UNESCAPED_UNICODE);
    } catch (Throwable $exception) {
        http_response_code(500);
        echo json_encode([
            'ok' => false,
            'error' => 'Gagal sinkronisasi. Periksa log PHP.',
        ]);
        error_log($exception->getMessage());
    }
    exit;
}

if (signed_in()) {
    // Saat halaman dibuka, ambil event terbaru. Cron tetap disarankan.
    require_once __DIR__ . '/worker.php';
    try {
        run_collect();
    } catch (Throwable $exception) {
        $error = 'Collector: ' . $exception->getMessage();
    }
}

function badge(string $severity): string
{
    $style = strtolower($severity);
    return '<span class="badge ' . html($style) . '">'
        . html($severity) . '</span>';
}

function action_form(string $ip, ?int $alertId = null): string
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return '<span class="muted">IP tidak tersedia</span>';
    }
    if (remote_mode() && !mitigation_ready()) {
        return '<span class="muted">Remote Block belum aktif</span>';
    }
    if (remote_mode() && !filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return '<span class="muted">IP lokal/privat tidak dapat diblokir</span>';
    }
    $form = '<form method="post" class="inline-action">';
    $form .= csrf_input();
    $form .= '<input type="hidden" name="action" value="block">';
    $form .= '<input type="hidden" name="ip" value="' . html($ip) . '">';
    if ($alertId) {
        $form .= '<input type="hidden" name="alert_id" value="'
            . $alertId . '">';
    }
    $form .= '<button class="button danger small" type="submit" '
        . 'data-confirm="Blokir sumber ' . html($ip)
        . ' selama maksimal 24 jam?">'
        . '<i data-feather="shield-off"></i> Block IP</button></form>';
    return $form;
}

if ($page === 'login') {
    require __DIR__ . '/pages/login.php';
    exit;
}

$alerts = query_all(
    siem(),
    'SELECT a.*, l.event_type, l.actor, l.country, '
    . 'l.event_time, l.details_json '
    . 'FROM alerts a JOIN logs l ON l.id = a.log_id '
    . 'ORDER BY a.id DESC LIMIT 100'
);
try {
    $blocks = get_blocks();
} catch (Throwable $exception) {
    $blocks = [];
    $error = 'Status blokir Hostinger tidak dapat dibaca: ' . $exception->getMessage();
}
$logs = [];
$logTotal = 0;
$logPage = 1;
$logPageSize = 50;
$logPageCount = 1;
$logFrom = is_string($_GET['from'] ?? null) ? trim($_GET['from']) : '';
$logTo = is_string($_GET['to'] ?? null) ? trim($_GET['to']) : '';
$logSearch = is_string($_GET['q'] ?? null) ? trim($_GET['q']) : '';
$logFilterError = '';
$logPreviousUrl = 'index.php?page=logs';
$logNextUrl = 'index.php?page=logs';
$rules = [];
$eventTypes = [];
if ($page === 'logs') {
    $perPageValue = $_GET['per_page'] ?? '50';
    $perPage = filter_var(
        is_string($perPageValue) || is_int($perPageValue)
            ? $perPageValue : '',
        FILTER_VALIDATE_INT
    );
    if (in_array($perPage, [25, 50, 100], true)) {
        $logPageSize = $perPage;
    }

    $requestedPage = filter_var(
        is_string($_GET['log_page'] ?? null) ? $_GET['log_page'] : '1',
        FILTER_VALIDATE_INT
    );
    $logPage = $requestedPage === false || $requestedPage < 1
        ? 1 : $requestedPage;

    $parseDate = static function (
        string $value,
        DateTimeZone $zone
    ): ?DateTimeImmutable {
        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value, $zone);
        $errors = DateTimeImmutable::getLastErrors();
        if (!$date || ($errors !== false
            && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
            || $date->format('Y-m-d') !== $value) {
            return null;
        }
        return $date;
    };
    $zone = new DateTimeZone('Asia/Jakarta');
    $fromDate = $logFrom !== '' ? $parseDate($logFrom, $zone) : null;
    $toDate = $logTo !== '' ? $parseDate($logTo, $zone) : null;
    if (($logFrom !== '' && !$fromDate) || ($logTo !== '' && !$toDate)) {
        $logFilterError = 'Format tanggal tidak valid.';
    } elseif ($fromDate && $toDate && $fromDate > $toDate) {
        $logFilterError = 'Tanggal mulai tidak boleh melewati tanggal akhir.';
    }
    if ($logFilterError !== '') {
        $error = $logFilterError;
    } else {
        $conditions = [];
        $values = [];
        if ($fromDate) {
            $conditions[] = 'event_time >= ?';
            $values[] = $fromDate->getTimestamp();
        }
        if ($toDate) {
            $conditions[] = 'event_time <= ?';
            $values[] = $toDate->modify('+1 day')->getTimestamp() - 1;
        }
        if ($logSearch !== '') {
            $conditions[] = '(source LIKE ? OR event_type LIKE ? '
                . 'OR actor LIKE ? OR ip LIKE ? OR country LIKE ?)';
            $searchPattern = '%' . $logSearch . '%';
            array_push(
                $values,
                $searchPattern,
                $searchPattern,
                $searchPattern,
                $searchPattern,
                $searchPattern
            );
        }
        $where = $conditions ? ' WHERE ' . implode(' AND ', $conditions) : '';
        $totalRow = query_one(
            siem(),
            'SELECT COUNT(*) AS total FROM logs' . $where,
            $values
        );
        $logTotal = (int) ($totalRow['total'] ?? 0);
        $logPageCount = max(
            1,
            (int) ceil($logTotal / $logPageSize)
        );
        $logPage = min($logPage, $logPageCount);
        $offset = ($logPage - 1) * $logPageSize;
        $logs = query_all(
            siem(),
            'SELECT * FROM logs' . $where
                . ' ORDER BY event_time DESC, id DESC'
                . ' LIMIT ' . $logPageSize . ' OFFSET ' . $offset,
            $values
        );

        $pageParams = [
            'page' => 'logs',
            'per_page' => $logPageSize,
        ];
        if ($logFrom !== '') {
            $pageParams['from'] = $logFrom;
        }
        if ($logTo !== '') {
            $pageParams['to'] = $logTo;
        }
        if ($logSearch !== '') {
            $pageParams['q'] = $logSearch;
        }
        $logPreviousUrl = 'index.php?' . http_build_query(
            $pageParams + ['log_page' => max(1, $logPage - 1)]
        );
        $logNextUrl = 'index.php?' . http_build_query(
            $pageParams + ['log_page' => min($logPageCount, $logPage + 1)]
        );
    }
}
if ($page === 'rules') {
    $rules = query_all(siem(), 'SELECT * FROM rules ORDER BY id');
    $eventTypes = query_all(
        siem(),
        'SELECT DISTINCT event_type FROM logs ORDER BY event_type LIMIT 100'
    );
}
$activeBlocks = count(array_filter(
    $blocks, fn ($row) => $row['status'] === 'Active'
));
$severityCounts = ['High' => 0, 'Medium' => 0, 'Low' => 0];
foreach ($alerts as $alert) {
    $name = $alert['severity'];
    if (isset($severityCounts[$name])) {
        $severityCounts[$name]++;
    }
}
$pages = [
    'dashboard' => ['Overview', 'layout-dashboard'],
    'audit' => ['Audit & Mitigasi', 'shield-alert'],
    'logs' => ['Event Logs', 'file-text'],
    'blocks' => ['Blocked IPs', 'shield-off'],
    'rules' => ['Detection Rules', 'sliders'],
];
$pageTemplates = [
    'dashboard' => __DIR__ . '/pages/overview.php',
    'audit' => __DIR__ . '/pages/audit.php',
    'logs' => __DIR__ . '/pages/logs.php',
    'blocks' => __DIR__ . '/pages/blocks.php',
    'rules' => __DIR__ . '/pages/rules.php',
];
?><!DOCTYPE html><html lang="id"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= html($pages[$page][0]) ?> · ZenPrimax SIEM</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet"
    href="https://fonts.googleapis.com/css2?family=Roboto:wght@100..900&display=swap">
<link rel="stylesheet" href="assets/style.css?v=28">
</head><body>
<div class="layout">
<div class="sidebar-shade" id="sidebar-shade"></div>
<aside class="sidebar" id="sidebar">
    <div class="brand"><div class="brand-symbol">
        <img src="assets/logo-siem.png" alt="ZenPrimax SIEM"></div>
        <div><b>ZenPrimax</b><small>Security Monitor.</small></div>
    </div>
    <p class="menu-label">Menu Utama</p>
    <nav class="nav">
        <?php foreach ($pages as $key => $item): ?>
        <a class="<?= $page === $key ? 'selected' : '' ?>"
            href="index.php?page=<?= html($key) ?>">
            <i data-feather="<?= html($item[1]) ?>"></i>
            <?= html($item[0]) ?>
        </a>
        <?php endforeach; ?>
    </nav>
</aside>
<main class="main">
    <header class="topbar">
        <div class="topbar-heading">
            <button class="mobile-menu icon-button" type="button"
                id="menu-toggle" aria-label="Buka navigasi"
                aria-expanded="false">
                <i data-feather="menu"></i>
            </button>
            <div>
            <h1><?= html($pages[$page][0]) ?></h1></div></div>
        <div class="top-actions">
            <a class="button secondary small" href="report.php">
                <i data-feather="download"></i> Laporan PDF
            </a>
            <form method="post">
                <?= csrf_input() ?>
                <input type="hidden" name="action" value="logout">
                <button class="icon-button" type="submit" title="Keluar dari SIEM"
                    aria-label="Keluar dari SIEM">
                    <i data-feather="log-out"></i>
                </button>
            </form>
        </div>
    </header>
    <?php if ($error): ?>
        <div class="notice error"><?= html($error) ?></div>
    <?php endif; ?>
    <?php if (!empty($_GET['notice'])): ?>
        <div class="notice success"><?= html($_GET['notice']) ?></div>
    <?php endif; ?>

<?php require $pageTemplates[$page]; ?>
<footer class="footer"><span>© ZenPrimax SIEM Lab · Security Monitoring</span>
    <span>Estimasi negara berdasarkan GeoIP, bukan lokasi fisik pasti.</span>
</footer>
</main></div>
<script src="https://unpkg.com/feather-icons/dist/feather.min.js"></script>
<script src="assets/app.js?v=14" defer></script>
</body></html>
