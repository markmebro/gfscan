<?php
// Tampilkan error PHP (untuk debugging)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$minute = 15;
$limit = (60 * $minute);
ini_set('memory_limit', '-1');
ini_set('max_execution_time', $limit);
set_time_limit($limit);

function recursiveScan($directory, &$entries_array = array())
{
    $handle = @opendir($directory);
    if ($handle) {
        while (($entry = readdir($handle)) !== false) {
            if ($entry == '.' || $entry == '..') continue;
            $entryPath = $directory . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($entryPath) && is_readable($entryPath) && !is_link($entryPath)) {
                $entries_array = recursiveScan($entryPath, $entries_array);
            } elseif (is_file($entryPath) && is_readable($entryPath)) {
                $entries_array['file_writable'][] = $entryPath;
            } else {
                $entries_array['file_not_writable'][] = $entryPath;
            }
        }
        closedir($handle);
    }
    return $entries_array;
}

function sortByLastModified($files)
{
    @array_multisort(array_map('filemtime', $files), SORT_DESC, $files);
    return $files;
}

function getSortedByTime($path)
{
    $result = recursiveScan($path);
    $fileWritable = isset($result['file_writable']) ? $result['file_writable'] : [];
    $fileNotWritable = isset($result['file_not_writable']) ? $result['file_not_writable'] : [];

    $fileWritable = sortByLastModified($fileWritable);
    return [
        'file_writable' => $fileWritable,
        'file_not_writable' => $fileNotWritable
    ];
}

function getSortedByExtension($path, $ext)
{
    $result = getSortedByTime($path);
    $fileWritable = $result['file_writable'];
    $sortedWritableFile = [];

    foreach ($fileWritable as $entry) {
        $extension = strtolower(pathinfo($entry, PATHINFO_EXTENSION));
        if (in_array($extension, $ext)) {
            $sortedWritableFile[] = $entry;
        }
    }

    return [
        'file_writable' => $sortedWritableFile,
        'file_not_writable' => []
    ];
}

function getFileTokens($filename)
{
    $fileContent = file_get_contents($filename);
    $fileContent = preg_replace('/<\?([^p=\w])/m', '<?php ', $fileContent);
    $token = token_get_all($fileContent);
    $output = [];
    foreach ($token as $tok) {
        if (isset($tok[1])) {
            $output[] = strtolower($tok[1]);
        }
    }
    return array_values(array_unique(array_filter(array_map("trim", $output))));
}

function compareTokens($needles, $haystack)
{
    $output = [];
    foreach ($needles as $n) {
        if (in_array($n, $haystack)) {
            $output[] = $n;
        }
    }
    return $output;
}

$ext = ['php', 'phps', 'pht', 'phpt', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8', 'suspected'];
$tokenNeedles = [
    'base64_decode',
    'rawurldecode',
    'urldecode',
    'gzinflate',
    'gzuncompress',
    'str_rot13',
    'convert_uu',
    'htmlspecialchars_decode',
    'bin2hex',
    'hex2bin',
    'hexdec',
    'chr',
    'strrev',
    'goto',
    'implode',
    'strtr',
    'extract',
    'parse_str',
    'substr',
    'mb_substr',
    'str_replace',
    'substr_replace',
    'preg_replace',
    'exif_read_data',
    'readgzfile',
    'eval',
    'exec',
    'shell_exec',
    'system',
    'passthru',
    'pcntl_fork',
    'fsockopen',
    'proc_open',
    'popen',
    'assert',
    'posix_kill',
    'posix_setpgid',
    'posix_setsid',
    'posix_setuid',
    'proc_nice',
    'proc_close',
    'proc_terminate',
    'apache_child_terminate',
    'posix_getuid',
    'posix_geteuid',
    'posix_getegid',
    'posix_getpwuid',
    'posix_getgrgid',
    'posix_mkfifo',
    'posix_getlogin',
    'posix_ttyname',
    'getenv',
    'proc_get_status',
    'get_cfg_var',
    'disk_free_space',
    'disk_total_space',
    'diskfreespace',
    'getlastmo',
    'getmyinode',
    'getmypid',
    'getmyuid',
    'getmygid',
    'fileowner',
    'filegroup',
    'get_current_user',
    'pathinfo',
    'getcwd',
    'sys_get_temp_dir',
    'basename',
    'phpinfo',
    'mysql_connect',
    'mysqli_connect',
    'mysqli_query',
    'mysql_query',
    'fopen',
    'fsockopen',
    'file_put_contents',
    'file_get_contents',
    'url_get_contents',
    'stream_get_meta_data',
    'move_uploaded_file',
    '$_files',
    'copy',
    'include',
    'include_once',
    'require',
    'require_once',
    '__file__',
    'mail',
    'putenv',
    'curl_init',
    'tmpfile',
    'allow_url_fopen',
    'ini_set',
    'set_time_limit',
    'session_start',
    'symlink',
    '__halt_compiler',
    '__compiler_halt_offset__',
    'error_reporting',
    'create_function',
    'get_magic_quotes_gpc',
    '$auth_pass',
    '$password'
];

function hasSuspiciousString($content)
{
    $patterns = [
        '/\$[a-z0-9_]+\s*=\s*[\'"]?base64_decode/i',
        '/eval\s*\(\s*\$/i',
        '/\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]/i',
        '/preg_replace\s*\(\s*.*\/e.*\)/i',
        '/\b(system|shell_exec|passthru|proc_open|popen|assert)\b/i',
        '/gzinflate|str_rot13|gzuncompress|create_function/i',
        '/\$\$[a-zA-Z0-9_]+/i', // variable variables
        '/include(_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/header\s*\(\s*[\'"](HTTP\/1\.[01]) (403|404)/i',
        '/[\'"][0-9a-f]{20,}[\'"]/i', // hex encoded long strings
    ];

    $matched = [];
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $content, $m)) {
            $matched[] = $m[0];
        }
    }

    return $matched;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (isset($_POST['deletePath'])) {
        $fileToDelete = realpath($_POST['deletePath']);
        header('Content-Type: application/json');

        if (!$fileToDelete || !is_file($fileToDelete)) {
            echo json_encode(['success' => false, 'message' => 'File tidak ditemukan atau path tidak valid.']);
            exit;
        }

        if (!is_writable($fileToDelete)) {
            echo json_encode(['success' => false, 'message' => 'File tidak bisa dihapus (tidak writable).']);
            exit;
        }

        if (!isset($_POST['confirm'])) {
            echo json_encode(['success' => false, 'message' => 'confirm']);
            exit;
        }

        if (unlink($fileToDelete)) {
            echo json_encode(['success' => true, 'message' => 'File berhasil dihapus.']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Gagal menghapus file.']);
        }
        exit;
    }


    if (isset($_POST['urls'])) {
        // Check multiple URLs status 200 with curl_multi
        $urls = json_decode($_POST['urls'], true);
        $multiHandle = curl_multi_init();
        $curlHandles = [];
        $results = [];

        foreach ($urls as $i => $url) {
            if (!preg_match('~^https?://~i', $url)) $url = "http://$url";
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_USERAGENT => 'Mozilla/5.0',
                CURLOPT_NOBODY => true,
            ]);
            curl_multi_add_handle($multiHandle, $ch);
            $curlHandles[$i] = $ch;
        }

        $running = null;
        do {
            curl_multi_exec($multiHandle, $running);
            curl_multi_select($multiHandle);
        } while ($running > 0);

        foreach ($curlHandles as $i => $ch) {
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if ($httpCode === 200) {
                $results[] = $urls[$i];
            }
            curl_multi_remove_handle($multiHandle, $ch);
            curl_close($ch);
        }

        curl_multi_close($multiHandle);

        header('Content-Type: application/json');
        echo json_encode([
            'totalScanned' => count($urls),
            'totalActive' => count($results),
            'activeUrls' => $results,
        ]);
        exit;
    }

    // Deep Check + Deep Scan keyword combined
    if (isset($_POST['deepCheckUrl'])) {
        $url = $_POST['deepCheckUrl'];
        if (!preg_match('~^https?://~i', $url)) $url = "http://$url";

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_USERAGENT => 'Mozilla/5.0',
        ]);
        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // Jika hanya ingin tahu apakah URL aktif dan ada konten
        if (!isset($_POST['checkKeyword'])) {
            header('Content-Type: application/json');
            echo json_encode([
                'url' => $url,
                'hasContent' => trim($body) !== '' && $status === 200,
            ]);
            exit;
        }

        // Jika ingin tahu apakah keyword mencurigakan ditemukan
        $keywords = ['upload', 'login', 'password', 'input', 'IP', 'serverIP', 'php', 'sql', 'choose a file', 'dumper', 'submit', 'form', 'button'];
        $found = false;

        foreach ($keywords as $word) {
            if (stripos($body, $word) !== false) {
                $found = true;
                break;
            }
        }

        header('Content-Type: application/json');
        echo json_encode([
            'url' => $url,
            'matched' => $found && $status === 200,
        ]);
        exit;
    }

}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <title>APLIKASI CARI KUTU JEMBUT</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
    <style>
        body {
            font-family: 'Ubuntu Mono', monospace;
            background-color: #f8f9fa;
        }

        textarea {
            font-family: 'Ubuntu Mono', monospace;
            white-space: pre;
            overflow-x: auto;
            overflow-y: auto;
            resize: vertical;
            min-height: 300px;
        }

        textarea {
            font-family: monospace;
            resize: vertical;
        }

        .spinner-border-sm {
            width: 1.5rem;
            height: 1.5rem;
        }
    </style>
</head>

<body>
    <div class="container my-5">
        <div class="text-center mb-4">
            <h1 class="display-5 fw-bold text-secondary">APLIKASI CARI KUTU JEMBUT</h1>
        </div>

        <form method="post" class="mb-4">
            <span>Directory</span>
            <div class="row g-2 mb-3">
                <div class="col-md-8">
                    <input type="text" class="form-control" name="dir" value="<?= htmlspecialchars(getcwd()) ?>" placeholder="Masukkan direktori..." />
                </div>
                <div class="col-md-2 d-grid">
                    <button type="submit" name="submit" class="btn btn-primary">Scan</button>
                </div>
                <div class="col-md-2 d-grid">
                    <button type="button" class="btn btn-info btn-sm" onclick="removeAfterDirectory()">📁 Dir</button>
                </div>
            </div>
        </form>

        <?php if (isset($_POST['submit'])):
            $output = "";
            $path = $_POST['dir'];
            $result = getSortedByExtension($path, $ext);
            $fileWritable = sortByLastModified($result['file_writable']);
            foreach ($fileWritable as $file) {
                $filePath = str_replace('\\', '/', $file);
                $tokens = getFileTokens($filePath);
                $cmp = compareTokens($tokenNeedles, $tokens);

                $content = @file_get_contents($filePath, false, null, 0, 10000); // baca 10KB awal saja
                $regexHits = hasSuspiciousString($content);

                if (!empty($cmp) || !empty($regexHits)) {
                    $matches = array_merge($cmp, $regexHits);
                    $output .= "$filePath (" . implode(', ', array_unique($matches)) . ')' . PHP_EOL;
                }
            }
        endif;
        ?>

        <div class="row g-2">
            <div class="col-md-5">
                <span>Find</span>
            </div>
            <div class="col-md-5">
                <span>Replace</span>
            </div>
            <div class="col-md-2 d-grid"></div>
        </div>
        <div class="row g-2 mb-3">
            <div class="col-md-5">
                <input type="text" id="findText" class="form-control" value="<?= htmlspecialchars(getcwd()) ?>/" placeholder="Find..." />
            </div>
            <div class="col-md-5">
                <input type="text" id="replaceText" class="form-control" placeholder="Replace with..." />
            </div>
            <div class="col-md-2 d-grid">
                <button type="button" class="btn btn-warning" onclick="replaceInTextarea()">🔄 Replace</button>
            </div>
        </div>

        <form id="urlForm">
            <div class="mb-3">
                <textarea id="result" class="form-control" style="height: 200px;"><?= htmlspecialchars($output) ?></textarea>
            </div>

            <div class="d-flex gap-2 flex-wrap mb-3">
                <button type="button" class="btn btn-primary" id="deepcheckBtn">
                    Deep Check
                    <span id="checkSpinner" class="spinner-border spinner-border-sm d-none" role="status"></span>
                </button>
                <button type="button" class="btn btn-danger" id="deepscanBtn">
                    Deep Scan
                    <span id="scanSpinner" class="spinner-border spinner-border-sm d-none" role="status"></span>
                </button>
            </div>
        </form>

        <div id="stats" class="mt-3" style="display:none;">
            <p><strong>Total URLs scanned:</strong> <span id="totalScanned">0</span></p>
            <p><strong>Total URLs active (200):</strong> <span id="totalActive">0</span></p>
        </div>

        <div id="resultBox" class="mt-3 d-none">
            <h5>✔️ Active URLs</h5>
            <textarea class="form-control" id="result2" rows="10" style="height: 200px;"></textarea>
            <div id="batchStatus" class="mt-2 fst-italic text-muted d-flex justify-content-between">
                <div id="batchTotalChecking">Total checking (0/0)</div>
                <div id="batchEstimatingTime">Estimating time (00:00:00)</div>
                <div id="batchDurationCheck">Duration check (00:00:00)</div>
            </div>
        </div>
        <hr>
        <h4>🗑️ Hapus File</h4>
        <div class="row g-2 mb-2">
            <div class="col-md-10">
                <input type="text" id="deletePath" class="form-control" placeholder="Contoh: /var/www/html/file.php">
            </div>
            <div class="col-md-2 d-grid">
                <button class="btn btn-danger" onclick="deleteFile()">Hapus</button>
            </div>
        </div>
        <div id="deleteStatus" class="text-muted fst-italic"></div>
    </div>

    <script>
        function removeAfterDirectory() {
            let textarea = document.getElementById("result");
            let lines = textarea.value.split('\n');
            let processed = lines.map(line => line.replace(/\s*\(.*$/, '').trim());
            textarea.value = processed.join('\n');
        }

        function replaceInTextarea() {
            let find = document.getElementById("findText").value;
            let replace = document.getElementById("replaceText").value;
            let textarea = document.getElementById("result");
            if (!find) {
                alert('Find text tidak boleh kosong');
                return;
            }
            let content = textarea.value;
            let regex = new RegExp(find.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
            textarea.value = content.replace(regex, replace);
        }

        function deleteFile() {
            let path = document.getElementById("deletePath").value.trim();
            if (!path) {
                alert('Path kosong!');
                return;
            }
            if (!confirm(`Apakah yakin ingin menghapus file:\n${path}?`)) return;

            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    'deletePath': path,
                    'confirm': 'yes'
                })
            }).then(res => res.json())
                .then(data => {
                    document.getElementById('deleteStatus').textContent = data.message;
                })
                .catch(e => {
                    document.getElementById('deleteStatus').textContent = 'Error: ' + e.message;
                });
        }

        // Deep Check (cek URL satu per satu untuk keyword + status 200)
        document.getElementById('deepcheckBtn').addEventListener('click', async () => {
            const textarea = document.getElementById('result');
            const urls = textarea.value.trim().split('\n').filter(l => l.trim());
            if (urls.length === 0) {
                alert('Textarea kosong');
                return;
            }
            document.getElementById('checkSpinner').classList.remove('d-none');
            let result2 = document.getElementById('result2');
            result2.value = '';
            let foundUrls = [];

            for (let i = 0; i < urls.length; i++) {
                const url = urls[i].trim();
                try {
                    const resp = await fetch('', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                        body: new URLSearchParams({
                            'deepCheckUrl': url,
                            'checkKeyword': '1'
                        })
                    });
                    const data = await resp.json();
                    if (data.matched) {
                        foundUrls.push(data.url);
                        result2.value += data.url + '\n';
                    }
                } catch {
                    // ignore errors
                }
            }

            document.getElementById('checkSpinner').classList.add('d-none');
            if (foundUrls.length === 0) {
                result2.value = '(No matched URLs)';
            }
            document.getElementById('resultBox').classList.remove('d-none');
        });

        // Deep Scan (cek status 200 URL dengan curl_multi di backend)
        document.getElementById('deepscanBtn').addEventListener('click', async () => {
            const textarea = document.getElementById('result');
            const urls = textarea.value.trim().split('\n').filter(l => l.trim());
            if (urls.length === 0) {
                alert('Textarea kosong');
                return;
            }

            document.getElementById('scanSpinner').classList.remove('d-none');
            document.getElementById('resultBox').classList.add('d-none');
            document.getElementById('stats').style.display = 'block';
            document.getElementById('totalScanned').textContent = urls.length;
            document.getElementById('totalActive').textContent = 0;

            try {
                const resp = await fetch('', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: new URLSearchParams({'urls': JSON.stringify(urls)})
                });
                const data = await resp.json();
                document.getElementById('totalActive').textContent = data.totalActive;
                let result2 = document.getElementById('result2');
                result2.value = data.activeUrls.join('\n');
                document.getElementById('resultBox').classList.remove('d-none');
            } catch (e) {
                alert('Error saat Deep Scan: ' + e.message);
            }
            document.getElementById('scanSpinner').classList.add('d-none');
        });
    </script>
</body>

</html>
