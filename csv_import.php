<?php
// Import CSV audit website dan request Vercel ke tabel log SIEM.

function csv_source_id(string $identity): int
{
    return (int) hexdec(substr(hash('sha256', $identity), 0, 15));
}

function csv_text(string $value): string
{
    $value = trim($value);
    if (strlen($value) > 1000) {
        if (function_exists('mb_strcut')) {
            $value = mb_strcut($value, 0, 1000, 'UTF-8');
        } else {
            $value = substr($value, 0, 1000);
            while ($value !== '' && !preg_match('//u', $value)) {
                $value = substr($value, 0, -1);
            }
        }
    }
    return $value;
}

function csv_clip(string $value, int $length): string
{
    if (strlen($value) <= $length) {
        return $value;
    }
    if (function_exists('mb_strcut')) {
        return mb_strcut($value, 0, $length, 'UTF-8');
    }
    $value = substr($value, 0, $length);
    while ($value !== '' && !preg_match('//u', $value)) {
        $value = substr($value, 0, -1);
    }
    return $value;
}

function csv_row_time(string $value, string $format): int
{
    if ($format === 'audit') {
        $months = [
            'jan' => '01', 'feb' => '02', 'mar' => '03', 'apr' => '04',
            'mei' => '05', 'may' => '05', 'jun' => '06', 'jul' => '07',
            'agu' => '08', 'aug' => '08', 'sep' => '09', 'okt' => '10',
            'oct' => '10', 'nov' => '11', 'des' => '12', 'dec' => '12',
        ];
        if (!preg_match(
            '/^(\d{1,2})\s+([A-Za-z]+)\s+(\d{4}),\s*(\d{1,2})\.(\d{2})\.(\d{2})$/',
            trim($value),
            $match
        )) {
            throw new RuntimeException('Format Waktu (WIB) CSV audit tidak valid.');
        }
        $month = $months[strtolower($match[2])] ?? null;
        if ($month === null) {
            throw new RuntimeException('Nama bulan Waktu (WIB) tidak dikenali.');
        }
        $date = sprintf(
            '%04d-%02d-%02d %02d:%02d:%02d',
            (int) $match[3], (int) $month, (int) $match[1],
            (int) $match[4], (int) $match[5], (int) $match[6]
        );
        $zone = new DateTimeZone('Asia/Jakarta');
    } else {
        $date = trim($value);
        $zone = new DateTimeZone('UTC');
    }

    $time = DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', $date, $zone);
    $errors = DateTimeImmutable::getLastErrors();
    if (!$time || ($errors !== false
        && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
        || $time->format('Y-m-d H:i:s') !== $date) {
        throw new RuntimeException('Waktu event pada CSV tidak valid.');
    }
    return $time->getTimestamp();
}

function parse_log_csv(string $path): array
{
    $file = fopen($path, 'rb');
    if (!$file) {
        throw new RuntimeException('File CSV tidak dapat dibaca.');
    }
    try {
        $headers = fgetcsv($file, 0, ',', '"', '');
        if (!is_array($headers) || !$headers) {
            throw new RuntimeException('File CSV kosong atau header tidak ditemukan.');
        }
        $headers[0] = preg_replace('/^\xEF\xBB\xBF/', '', (string) $headers[0]);
        $headers = array_map(
            static fn ($value) => trim((string) $value),
            $headers
        );
        if (count(array_unique($headers)) !== count($headers)) {
            throw new RuntimeException('CSV memiliki nama kolom yang berulang.');
        }

        $auditColumns = [
            'ID Log', 'Waktu (WIB)', 'Aktor', 'Email Aktor',
            'Peran', 'Aksi', 'Entitas Target', 'Deskripsi',
            'Alamat IP', 'Perangkat & OS',
        ];
        $vercelColumns = [
            'timestampInMs', 'requestPath', 'requestMethod',
            'responseStatusCode', 'requestId',
        ];
        if (!array_diff($auditColumns, $headers)) {
            $format = 'audit';
            $source = 'audit_csv';
        } elseif (!array_diff($vercelColumns, $headers)) {
            $format = 'vercel';
            $source = 'vercel_csv';
        } else {
            throw new RuntimeException(
                'Format CSV tidak dikenali. Gunakan ekspor audit website '
                . 'atau Vercel CDN Requests.'
            );
        }

        $events = [];
        $line = 1;
        while (($values = fgetcsv($file, 0, ',', '"', '')) !== false) {
            $line++;
            if (count($values) === 1 && trim((string) $values[0]) === '') {
                continue;
            }
            if (count($values) !== count($headers)) {
                throw new RuntimeException(
                    'Jumlah kolom CSV tidak konsisten pada baris ' . $line . '.'
                );
            }
            foreach ($values as $value) {
                if (!is_string($value) || !preg_match('//u', $value)
                    || str_contains($value, "\0")) {
                    throw new RuntimeException(
                        'CSV harus berisi teks UTF-8 yang valid (baris '
                        . $line . ').'
                    );
                }
            }
            $row = array_combine($headers, $values);
            if (!is_array($row)) {
                throw new RuntimeException('Format baris CSV tidak valid.');
            }
            $row = array_map(
                static fn ($value) => csv_text((string) $value),
                $row
            );

            if ($format === 'audit') {
                $externalId = $row['ID Log'];
                $type = $row['Aksi'];
                if ($externalId === '' || $type === '') {
                    throw new RuntimeException(
                        'ID Log dan Aksi wajib diisi (baris ' . $line . ').'
                    );
                }
                if (strlen($type) > 80) {
                    throw new RuntimeException(
                        'Nama Aksi melebihi 80 karakter (baris ' . $line . ').'
                    );
                }
                $ip = filter_var($row['Alamat IP'], FILTER_VALIDATE_IP)
                    ? $row['Alamat IP'] : 'unknown';
                $actor = $row['Aktor'] !== ''
                    ? $row['Aktor'] : $row['Email Aktor'];
                $events[] = [
                    'source' => $source,
                    'source_id' => csv_source_id('audit|' . $externalId),
                    'event_type' => $type,
                    'ip' => $ip,
                    'actor' => csv_clip($actor, 80),
                    'event_time' => csv_row_time($row['Waktu (WIB)'], 'audit'),
                    'details' => array_filter([
                        'log_id' => $externalId,
                        'actor_email' => $row['Email Aktor'],
                        'role' => $row['Peran'],
                        'target' => $row['Entitas Target'],
                        'description' => $row['Deskripsi'],
                        'device' => $row['Perangkat & OS'],
                    ], static fn ($value) => $value !== ''),
                ];
            } else {
                $millis = $row['timestampInMs'];
                if (!preg_match('/^\d{10,16}$/', $millis)) {
                    throw new RuntimeException(
                        'timestampInMs tidak valid (baris ' . $line . ').'
                    );
                }
                $time = intdiv((int) $millis, 1000);
                $status = filter_var(
                    $row['responseStatusCode'], FILTER_VALIDATE_INT
                );
                if ($time < 1 || $status === false || $status < 100
                    || $status > 599 || $row['requestPath'] === ''
                    || $row['requestId'] === '') {
                    throw new RuntimeException(
                        'Data request Vercel tidak lengkap (baris '
                        . $line . ').'
                    );
                }
                $type = $status >= 500
                    ? 'VERCEL_HTTP_5XX' : 'VERCEL_REQUEST';
                $identity = json_encode(
                    $row,
                    JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
                );
                if (!is_string($identity)) {
                    throw new RuntimeException(
                        'Identitas request Vercel gagal diproses.'
                    );
                }
                $events[] = [
                    'source' => $source,
                    'source_id' => csv_source_id('vercel|' . $identity),
                    'event_type' => $type,
                    'ip' => 'unknown',
                    'actor' => 'Vercel',
                    'event_time' => $time,
                    'details' => array_filter([
                        'time_utc' => $row['TimeUTC'] ?? '',
                        'request_id' => $row['requestId'],
                        'path' => $row['requestPath'],
                        'method' => $row['requestMethod'],
                        'query' => $row['requestQueryString'] ?? '',
                        'status' => (string) $status,
                        'user_agent' => $row['requestUserAgent'] ?? '',
                        'level' => $row['level'] ?? '',
                        'environment' => $row['environment'] ?? '',
                        'cache' => $row['vercelCache'] ?? '',
                        'type' => $row['type'] ?? '',
                        'function' => $row['function'] ?? '',
                        'host' => $row['host'] ?? '',
                        'deployment' => $row['deploymentDomain'] ?? '',
                        'duration_ms' => $row['durationMs'] ?? '',
                        'region' => $row['region'] ?? '',
                        'message' => $row['message'] ?? '',
                    ], static fn ($value) => $value !== ''),
                ];
            }

            if (count($events) > 5000) {
                throw new RuntimeException(
                    'Maksimal 5.000 baris data per file CSV.'
                );
            }
        }
        if (!$events) {
            throw new RuntimeException('CSV tidak memiliki baris data.');
        }
        return ['source' => $source, 'events' => $events];
    } finally {
        fclose($file);
    }
}

function import_log_csv_files(array $files): array
{
    if (!isset($files['name'], $files['tmp_name'], $files['error'])
        || !is_array($files['name']) || !is_array($files['tmp_name'])
        || !is_array($files['error'])) {
        throw new RuntimeException('Pilih setidaknya satu file CSV.');
    }
    $count = count($files['name']);
    if ($count < 1 || $count > 5
        || count($files['tmp_name']) !== $count
        || count($files['error']) !== $count) {
        throw new RuntimeException('Pilih 1 sampai 5 file CSV sekaligus.');
    }

    $imports = [];
    $totalBytes = 0;
    $totalRows = 0;
    for ($i = 0; $i < $count; $i++) {
        $name = (string) $files['name'][$i];
        $path = (string) $files['tmp_name'][$i];
        $error = (int) $files['error'][$i];
        if ($error !== UPLOAD_ERR_OK) {
            throw new RuntimeException(
                'Upload ' . basename($name) . ' gagal (kode ' . $error . ').'
            );
        }
        if (strtolower(pathinfo($name, PATHINFO_EXTENSION)) !== 'csv'
            || !is_uploaded_file($path)) {
            throw new RuntimeException(
                'Hanya file CSV yang diunggah melalui formulir ini yang diterima.'
            );
        }
        $size = filesize($path);
        if ($size === false || $size < 1 || $size > 10 * 1024 * 1024) {
            throw new RuntimeException(
                'Ukuran setiap CSV harus lebih dari 0 dan maksimal 10 MB.'
            );
        }
        $totalBytes += $size;
        if ($totalBytes > 25 * 1024 * 1024) {
            throw new RuntimeException('Total ukuran unggahan maksimal 25 MB.');
        }
        $parsed = parse_log_csv($path);
        $totalRows += count($parsed['events']);
        if ($totalRows > 10000) {
            throw new RuntimeException(
                'Maksimal 10.000 baris data untuk satu kali unggah.'
            );
        }
        $imports[] = $parsed;
    }

    $db = siem();
    $insert = $db->prepare(
        'INSERT IGNORE INTO logs '
        . '(source, source_id, event_type, ip, actor, country, '
        . 'event_time, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );
    $imported = 0;
    $duplicates = 0;
    $db->beginTransaction();
    try {
        foreach ($imports as $batch) {
            foreach ($batch['events'] as $event) {
                $ip = $event['ip'];
                $country = 'Tidak diketahui';
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $country = filter_var(
                        $ip,
                        FILTER_VALIDATE_IP,
                        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
                    ) ? 'Belum diperiksa' : 'Lokal / Privat / Simulasi';
                }
                $details = json_encode(
                    $event['details'],
                    JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
                );
                if (!is_string($details)) {
                    throw new RuntimeException('Detail event CSV gagal diproses.');
                }
                $insert->execute([
                    $event['source'], $event['source_id'],
                    $event['event_type'], $ip, $event['actor'],
                    $country, $event['event_time'], $details,
                ]);
                if ($insert->rowCount() === 0) {
                    $duplicates++;
                    continue;
                }
                $imported++;
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    detect(
                        (int) $db->lastInsertId(),
                        $event['event_type'],
                        $ip,
                        $event['event_time'],
                        false
                    );
                }
            }
        }
        $db->commit();
    } catch (Throwable $error) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        throw $error;
    }
    return ['imported' => $imported, 'duplicates' => $duplicates];
}
