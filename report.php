<?php
// Membuat laporan PDF terstruktur tanpa library tambahan.
require_once __DIR__ . '/common.php';
need_login();

function pdf_plain(string $value): string
{
    $value = preg_replace('/[\x00-\x1F]+/u', ' ', $value) ?? '';
    $ascii = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $value);
    $ascii = is_string($ascii) ? $ascii : $value;
    return preg_replace('/[^\x20-\x7E]/', '?', $ascii) ?? '';
}

function pdf_escape(string $value): string
{
    return str_replace(
        ['\\', '(', ')'],
        ['\\\\', '\\(', '\\)'],
        pdf_plain($value)
    );
}

class AuditReportPdf
{
    private $pages = [];
    private $stream = '';
    private $pageNumber = 0;
    private $y = 0;

    public function __construct()
    {
        $this->newPage();
    }

    private function command(string $command): void
    {
        $this->stream .= $command . "\n";
    }

    private function rect(
        float $x,
        float $y,
        float $width,
        float $height,
        array $color
    ): void {
        $this->command(sprintf(
            '%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f',
            $color[0], $color[1], $color[2], $x, $y, $width, $height
        ));
    }

    private function rule(float $x1, float $y1, float $x2, float $y2): void
    {
        $this->command(
            "0.82 0.85 0.90 RG 0.6 w "
            . sprintf('%.2f %.2f m %.2f %.2f l S', $x1, $y1, $x2, $y2)
        );
    }

    private function text(
        float $x,
        float $y,
        string $value,
        float $size = 9,
        bool $bold = false,
        array $color = [0.16, 0.20, 0.28]
    ): void {
        $font = $bold ? 'F2' : 'F1';
        $this->command(sprintf(
            'BT /%s %.1f Tf %.3f %.3f %.3f rg 1 0 0 1 %.2f %.2f Tm (%s) Tj ET',
            $font,
            $size,
            $color[0],
            $color[1],
            $color[2],
            $x,
            $y,
            pdf_escape($value)
        ));
    }

    private function newPage(): void
    {
        if ($this->pageNumber > 0) {
            $this->text(
                42,
                27,
                'ZenPrimax SIEM  |  Security Audit Report  |  Halaman '
                    . $this->pageNumber,
                7,
                false,
                [0.43, 0.48, 0.56]
            );
            $this->rule(42, 40, 553, 40);
            $this->pages[] = $this->stream;
        }

        $this->pageNumber++;
        $this->stream = '';
        $this->rect(0, 790, 595, 52, [0.08, 0.11, 0.18]);
        $this->rect(0, 786, 595, 4, [0.45, 0.40, 0.93]);
        $this->text(42, 812, 'ZENPRIMAX', 14, true, [1, 1, 1]);
        $this->text(
            42,
            798,
            'SECURITY INFORMATION & EVENT MANAGEMENT',
            7,
            false,
            [0.75, 0.78, 0.85]
        );
        $this->text(429, 807, 'INTERNAL REPORT', 8, true, [0.79, 0.81, 1]);
        $this->y = 760;
    }

    private function ensureSpace(float $height): void
    {
        if ($this->y - $height < 58) {
            $this->newPage();
        }
    }

    public function paragraph(
        string $value,
        float $size = 9,
        bool $bold = false,
        array $color = [0.16, 0.20, 0.28],
        float $lineHeight = 13,
        float $indent = 0
    ): void {
        $value = trim(pdf_plain($value));
        if ($value === '') {
            return;
        }

        $maxChars = max(20, (int) floor((511 - $indent) / ($size * 0.52)));
        $lines = [];
        foreach (explode("\n", $value) as $part) {
            $part = trim($part);
            if ($part === '') {
                $lines[] = '';
                continue;
            }
            foreach (explode("\n", wordwrap($part, $maxChars, "\n", true)) as $line) {
                $lines[] = $line;
            }
        }

        foreach ($lines as $line) {
            $this->ensureSpace($lineHeight);
            if ($line !== '') {
                $this->text(42 + $indent, $this->y, $line, $size, $bold, $color);
            }
            $this->y -= $lineHeight;
        }
    }

    public function section(string $title): void
    {
        $this->ensureSpace(34);
        $this->y -= 3;
        $this->rect(42, $this->y - 3, 3, 17, [0.45, 0.40, 0.93]);
        $this->text(53, $this->y, $title, 11, true, [0.10, 0.14, 0.22]);
        $this->y -= 13;
        $this->rule(42, $this->y, 553, $this->y);
        $this->y -= 16;
    }

    public function introduction(array $summary): void
    {
        $this->text(42, $this->y, 'LAPORAN AUDIT KEAMANAN', 21, true, [0.08, 0.11, 0.18]);
        $this->y -= 21;
        $this->paragraph(
            'Ringkasan pemantauan, temuan, evidence, dan tindakan mitigasi.',
            9,
            false,
            [0.40, 0.45, 0.53],
            13
        );
        $this->y -= 4;
        $this->paragraph(
            'Tanggal dibuat: ' . date('d M Y, H:i:s') . ' WIB',
            8,
            false,
            [0.32, 0.37, 0.45],
            12
        );
        $this->paragraph(
            'Cakupan: ' . ($summary['scope'] ?? 'Seluruh temuan terbaru'),
            8,
            false,
            [0.32, 0.37, 0.45],
            12
        );
        $this->y -= 8;

        $cardWidth = 160;
        $gap = 15;
        $metrics = [
            ['TOTAL LOG', (string) $summary['logs']],
            ['TEMUAN', (string) $summary['alerts']],
            ['IP DIBLOKIR AKTIF', (string) $summary['blocks']],
        ];
        foreach ($metrics as $index => $metric) {
            $x = 42 + ($index * ($cardWidth + $gap));
            $this->rect($x, $this->y - 47, $cardWidth, 43, [0.95, 0.96, 0.98]);
            $this->text($x + 11, $this->y - 20, $metric[0], 7, true, [0.42, 0.47, 0.55]);
            $this->text($x + 11, $this->y - 39, $metric[1], 15, true, [0.12, 0.16, 0.25]);
        }
        $this->y -= 62;

        $this->rect(42, $this->y - 45, 3, 42, [0.93, 0.65, 0.28]);
        $this->rect(45, $this->y - 45, 508, 42, [1.00, 0.97, 0.91]);
        $this->text(56, $this->y - 17, 'CATATAN INTERPRETASI', 8, true, [0.48, 0.34, 0.14]);
        $this->y -= 30;
        $this->paragraph(
            'Estimasi negara berdasarkan GeoIP bukan bukti lokasi aktor. '
                . 'Anomali perlu ditinjau bersama konteks dan tidak otomatis '
                . 'membuktikan terjadinya serangan.',
            8,
            false,
            [0.34, 0.31, 0.25],
            11,
            14
        );
        $this->y -= 7;
    }

    public function finding(array $alert): void
    {
        $this->ensureSpace(80);
        $severity = strtoupper((string) $alert['severity']);
        $severityColor = [0.22, 0.48, 0.38];
        if (strcasecmp($severity, 'HIGH') === 0) {
            $severityColor = [0.76, 0.25, 0.31];
        } elseif (strcasecmp($severity, 'MEDIUM') === 0) {
            $severityColor = [0.72, 0.45, 0.13];
        }

        $this->rect(42, $this->y - 5, 3, 20, [0.45, 0.40, 0.93]);
        $this->text(53, $this->y, 'TEMUAN #' . $alert['id'], 9, true);
        $this->text(450, $this->y, $severity, 8, true, $severityColor);
        $this->y -= 17;
        $this->paragraph((string) $alert['title'], 11, true, [0.08, 0.11, 0.18], 15);
        $this->paragraph(
            'Waktu deteksi: ' . date('d M Y H:i:s', (int) $alert['last_event_time'])
                . ' WIB  |  Jumlah event: ' . $alert['event_count'],
            8,
            false,
            [0.42, 0.47, 0.55],
            12
        );
        $this->paragraph(
            'IP sumber: ' . $alert['ip']
                . '  |  Negara (estimasi): ' . $alert['country'],
            8,
            false,
            [0.25, 0.30, 0.38],
            12
        );
        $this->paragraph(
            'Aktor: ' . $alert['actor'] . '  |  Jenis event: ' . $alert['event_type'],
            8,
            false,
            [0.25, 0.30, 0.38],
            12
        );
        $this->paragraph('Evidence', 8, true, [0.24, 0.28, 0.38], 12);
        $this->paragraph((string) $alert['details'], 8, false, [0.32, 0.36, 0.44], 11, 10);
        $this->paragraph('Rekomendasi mitigasi', 8, true, [0.24, 0.28, 0.38], 12);
        $this->paragraph(
            (string) $alert['recommendation'],
            8,
            false,
            [0.32, 0.36, 0.44],
            11,
            10
        );

        $evidence = json_decode($alert['details_json'] ?? '{}', true);
        if (is_array($evidence) && $evidence) {
            $this->paragraph('Rincian evidence', 8, true, [0.24, 0.28, 0.38], 12);
            foreach ($evidence as $key => $value) {
                $detail = is_scalar($value)
                    ? (string) $value
                    : (string) json_encode($value, JSON_UNESCAPED_UNICODE);
                $this->paragraph(
                    $key . ': ' . $detail,
                    7,
                    false,
                    [0.38, 0.42, 0.50],
                    10,
                    10
                );
            }
        }
        $this->y -= 6;
        $this->rule(42, $this->y, 553, $this->y);
        $this->y -= 15;
    }

    public function block(array $block): void
    {
        $this->paragraph(
            $block['ip'] . '  |  Status: ' . $block['status']
                . '  |  Berakhir: ' . $block['expires_at'] . ' UTC',
            8,
            true,
            [0.19, 0.24, 0.32],
            12
        );
        $this->paragraph(
            'Alasan: ' . $block['reason'],
            8,
            false,
            [0.39, 0.43, 0.50],
            11,
            10
        );
        $this->y -= 4;
    }

    public function notes(): void
    {
        $this->section('Metodologi dan batasan');
        $this->paragraph(
            'Deteksi menggunakan aturan berbasis threshold pada log aplikasi '
                . 'dan server. Status serta rekomendasi pada laporan merupakan '
                . 'bantuan investigasi dan tetap memerlukan verifikasi.',
            8,
            false,
            [0.32, 0.36, 0.44],
            12
        );
        $this->paragraph(
            'Pengujian pada localhost tidak membuktikan kemampuan deteksi '
                . 'DDoS terdistribusi.',
            8,
            false,
            [0.32, 0.36, 0.44],
            12
        );
    }

    public function output(): string
    {
        $this->text(
            42,
            27,
            'ZenPrimax SIEM  |  Security Audit Report  |  Halaman '
                . $this->pageNumber,
            7,
            false,
            [0.43, 0.48, 0.56]
        );
        $this->rule(42, 40, 553, 40);
        $this->pages[] = $this->stream;

        $objects = [];
        $objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
        $objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
        $objects[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>';
        $pageIds = [];
        $nextId = 5;

        foreach ($this->pages as $page) {
            $pageId = $nextId++;
            $contentId = $nextId++;
            $pageIds[] = $pageId;
            $objects[$pageId] = '<< /Type /Page /Parent 2 0 R '
                . '/MediaBox [0 0 595 842] /Resources '
                . '<< /Font << /F1 3 0 R /F2 4 0 R >> >> '
                . "/Contents $contentId 0 R >>";
            $objects[$contentId] = '<< /Length ' . strlen($page)
                . " >>\nstream\n" . $page . "\nendstream";
        }
        $objects[2] = '<< /Type /Pages /Count ' . count($pageIds)
            . ' /Kids [' . implode(' ', array_map(
                fn ($id) => "$id 0 R",
                $pageIds
            )) . '] >>';
        ksort($objects);

        $pdf = "%PDF-1.4\n";
        $offsets = [0];
        foreach ($objects as $id => $object) {
            $offsets[$id] = strlen($pdf);
            $pdf .= "$id 0 obj\n$object\nendobj\n";
        }
        $xref = strlen($pdf);
        $size = max(array_keys($objects)) + 1;
        $pdf .= "xref\n0 $size\n0000000000 65535 f \n";
        for ($id = 1; $id < $size; $id++) {
            $pdf .= sprintf('%010d 00000 n ', $offsets[$id] ?? 0) . "\n";
        }
        $pdf .= "trailer\n<< /Size $size /Root 1 0 R >>\n"
            . "startxref\n$xref\n%%EOF";
        return $pdf;
    }
}

$alertId = filter_var($_GET['alert'] ?? '', FILTER_VALIDATE_INT);
$sql = 'SELECT a.*, l.event_type, l.actor, l.country, '
    . 'l.details_json FROM alerts a '
    . 'JOIN logs l ON l.id = a.log_id ';
$values = [];
if ($alertId) {
    $sql .= 'WHERE a.id = ? ';
    $values[] = $alertId;
}
$sql .= 'ORDER BY a.id DESC LIMIT 100';
$alerts = query_all(siem(), $sql, $values);
$blocks = get_blocks();

$pdf = new AuditReportPdf();
$pdf->introduction([
    'scope' => $alertId ? 'Temuan #' . $alertId : 'Seluruh temuan terbaru',
    'logs' => count_rows('logs'),
    'alerts' => count($alerts),
    'blocks' => count(array_filter(
        $blocks,
        fn ($row) => $row['status'] === 'Active'
    )),
]);
$pdf->section('Ringkasan temuan');
if (!$alerts) {
    $pdf->paragraph('Tidak ada temuan yang tercatat untuk cakupan laporan ini.');
} else {
    foreach ($alerts as $alert) {
        $pdf->finding($alert);
    }
}

$pdf->section('Riwayat blokir (maksimal 20 terakhir)');
$recentBlocks = array_slice($blocks, 0, 20);
if (!$recentBlocks) {
    $pdf->paragraph('Tidak ada riwayat blokir yang tercatat.');
} else {
    foreach ($recentBlocks as $block) {
        $pdf->block($block);
    }
}
$pdf->notes();

$content = $pdf->output();
$filename = $alertId
    ? 'ZenPrimax-SIEM-Temuan-' . $alertId . '.pdf'
    : 'ZenPrimax-SIEM-Laporan-Audit.pdf';
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . strlen($content));
header('Cache-Control: no-store');
echo $content;
