<?php
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
			$entry = $directory . DIRECTORY_SEPARATOR . $entry;
			if (is_dir($entry) && is_readable($directory) && !is_link($directory)) {
				$entries_array = recursiveScan($entry, $entries_array);
			} elseif (is_file($entry) && is_readable($entry)) {
				$entries_array['file_writable'][] = $entry;
			} else {
				$entries_array['file_not_writable'][] = $entry;
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
	'popen ',
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['urls'])) {
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

    // Deep check route
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

        header('Content-Type: application/json');
        echo json_encode([
            'url' => $url,
            'hasContent' => trim($body) !== '' && $status === 200,
        ]);
        exit;
    }

    // Deep Check 3: keyword match
    if (isset($_POST['deepCheck3Url'])) {
        $url = $_POST['deepCheck3Url'];
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

				$keywords = ['upload', 'login', 'password', 'input', 'IP', 'serverIP', 'php', 'sql', 'choose a file', 'dumper',	'type="submit"', "type='submit'", 'form', 'button'];
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
	<meta charset="UTF-8">
	<title>APLIKASI CARI KUTU JEMBUT</title>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
	<style>
		body {
			font-family: 'Ubuntu Mono', monospace;
			background-color: #f8f9fa;
		}

		textarea {
			font-family: 'Ubuntu Mono',monospace;
			white-space: pre;
			overflow-x: auto;
			overflow-y: auto;
			resize: vertical;
			min-height: 300px;
		}

    textarea { font-family: monospace; resize: vertical; }
    .spinner-border-sm { width: 1.5rem; height: 1.5rem; }

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
					<input type="text" class="form-control" name="dir" value="<?= htmlspecialchars(getcwd()) ?>" placeholder="Masukkan direktori...">
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
				if (!empty($cmp)) {
					$output .= $filePath . ' (' . implode(', ', $cmp) . ')' . PHP_EOL;
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
			<div class="col-md-2 d-grid">
			</div>
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

			<div class="d-flex gap-2 flex-wrap">
				<button type="button" class="btn btn-primary" id="deepcheckBtn">
					Deep Check
					<span id="loadingSpinner" class="spinner-border spinner-border-sm d-none" role="status"></span>
				</button>
				<button type="button" class="btn btn-danger" id="deepscanBtn">
					Deep Scan
					<span id="deepSpinner3" class="spinner-border spinner-border-sm d-none" role="status"></span>
				</button>
			</div>

		</form>

		<div id="stats" class="mt-3" style="display:none;">
			<p><strong>Total URLs scanned:</strong> <span id="totalScanned">0</span></p>
			<p><strong>Total URLs active (200):</strong> <span id="totalActive">0</span></p>
		</div>

		<div id="resultBox" class="mt-3">
			<h5>✔️ Active URLs</h5>
			<textarea class="form-control" id="result2" rows="10" style="height: 200px;"></textarea>
			<div id="batchStatus" class="mt-2 fst-italic text-muted d-flex justify-content-between">
				<div id="batchTotalChecking">Total checking (0/0)</div>
				<div id="batchEstimatingTime">Estimating time (00:00:00)</div>
				<div id="batchDurationCheck">Duration check (00:00:00)</div>
			</div>

		</div>
	</div>

	<script>
		function removeAfterDirectory() {
			let textarea = document.getElementById("result");
			let lines = textarea.value.split('\n');
			let processed = lines.map(line => line.replace(/\s*\(.*$/, '').trim());
			textarea.value = processed.join('\n');
		}

		function replaceInTextarea() {
			const find = document.getElementById("findText").value;
			const replace = document.getElementById("replaceText").value;
			const textarea = document.getElementById("result");

			if (find === "") {
				alert("Input 'Find' tidak boleh kosong.");
				return;
			}

			const regex = new RegExp(find, "g");
			textarea.value = textarea.value.replace(regex, replace);
		}
		
			document.addEventListener("DOMContentLoaded", function () {
					const domain = window.location.origin + "/";
					document.getElementById("replaceText").value = domain;
			});


		const form = document.getElementById('urlForm');
		const resultBox = document.getElementById('resultBox');
		const resultArea = document.getElementById('result2');
		const spinner = document.getElementById('loadingSpinner');
		const deepSpinner = document.getElementById('deepSpinner');
		const deepSpinner3 = document.getElementById('deepSpinner3');
		const deepcheckBtn = document.getElementById('deepcheckBtn');
		const deepscanBtn = document.getElementById('deepscanBtn');
		const stats = document.getElementById('stats');
		const totalScannedSpan = document.getElementById('totalScanned');
		const totalActiveSpan = document.getElementById('totalActive');

		deepcheckBtn.addEventListener('click', async (e) => {
			e.preventDefault();

			const input = document.getElementById('result').value.trim();
			if (!input) return alert('Input kosong');

			const urls = input.split('\n').map(x => x.trim()).filter(Boolean);
			resultArea.value = '';
			resultBox.classList.remove('d-none');
			stats.style.display = 'none';

			deepcheckBtn.disabled = true;
			spinner.classList.remove('d-none');

			let validUrls = 0;
			let startTime = Date.now();

			for (let i = 0; i < urls.length; i++) {
				const url = urls[i];

				// Update total checking (kiri)
				document.getElementById('batchTotalChecking').textContent = `Total checking (${i + 1}/${urls.length})`;

				// Update estimating time (tengah)
				if (i > 0) {
					const elapsed = (Date.now() - startTime) / 1000; // detik
					const avgPerItem = elapsed / i;
					const remaining = avgPerItem * (urls.length - i);
					document.getElementById('batchEstimatingTime').textContent = `Estimating time (${formatTime(Math.round(remaining))})`;
				} else {
					document.getElementById('batchEstimatingTime').textContent = `Estimating time (calculating...)`;
				}

				// Update duration check (kanan)
				const duration = (Date.now() - startTime) / 1000;
				document.getElementById('batchDurationCheck').textContent = `Duration check (${formatTime(Math.round(duration))})`;

				try {
					const res = await fetch('', {
						method: 'POST',
						headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
						body: new URLSearchParams({ deepCheckUrl: url })
					});
					const data = await res.json();
					if (data.hasContent) {
						resultArea.value += data.url + '\n';
						validUrls++;
					}
				} catch (err) {
					console.error("Failed to check:", url);
				}
			}

			// Final update
			document.getElementById('batchTotalChecking').textContent = `Total checking (${urls.length}/${urls.length})`;
			document.getElementById('batchEstimatingTime').textContent = `Estimating time (00:00:00)`;
			const finalDuration = (Date.now() - startTime) / 1000;
			document.getElementById('batchDurationCheck').textContent = `Duration check (${formatTime(Math.round(finalDuration))})`;

			totalScannedSpan.textContent = urls.length;
			totalActiveSpan.textContent = validUrls;
			stats.style.display = 'block';

			deepcheckBtn.disabled = false;
			spinner.classList.add('d-none');
		});

		deepscanBtn.addEventListener('click', async () => {
			const input = document.getElementById('result2').value.trim();
			if (!input) return alert('Input kosong');

			const urls = input.split('\n').map(x => x.trim()).filter(x => x);
			resultArea.value = '';
			resultBox.classList.remove('d-none');

			deepscanBtn.disabled = true;
			deepSpinner3.classList.remove('d-none');

			let validUrls = 0;
			let startTime = Date.now();

			for (let i = 0; i < urls.length; i++) {
				// Update total checking (kiri)
				document.getElementById('batchTotalChecking').textContent = `Total checking (${i + 1}/${urls.length})`;

				// Update estimating time (tengah)
				if (i > 0) {
					const elapsed = (Date.now() - startTime) / 1000;
					const avgPerItem = elapsed / i;
					const remaining = avgPerItem * (urls.length - i);
					document.getElementById('batchEstimatingTime').textContent = `Estimating time (${formatTime(Math.round(remaining))})`;
				} else {
					document.getElementById('batchEstimatingTime').textContent = `Estimating time (calculating...)`;
				}

				// Update duration check (kanan)
				const duration = (Date.now() - startTime) / 1000;
				document.getElementById('batchDurationCheck').textContent = `Duration check (${formatTime(Math.round(duration))})`;

				document.getElementById('batchStatus').textContent = `Deep Scan 3 (${i+1}/${urls.length})...`;

				try {
					const res = await fetch('', {
						method: 'POST',
						headers: {'Content-Type': 'application/x-www-form-urlencoded'},
						body: new URLSearchParams({ deepCheck3Url: urls[i] })
					});

					const data = await res.json();
					if (data.matched) {
						resultArea.value += data.url + "\n";
						resultArea.scrollTop = resultArea.scrollHeight;
						validUrls++;
					}
				} catch (err) {
					console.error("Failed to check:", urls[i]);
				}
			}

			// Final update
			document.getElementById('batchTotalChecking').textContent = `Total checking (${urls.length}/${urls.length})`;
			document.getElementById('batchEstimatingTime').textContent = `Estimating time (00:00:00)`;
			const finalDuration = (Date.now() - startTime) / 1000;
			document.getElementById('batchDurationCheck').textContent = `Duration check (${formatTime(Math.round(finalDuration))})`;

			totalScannedSpan.textContent = urls.length;
			totalActiveSpan.textContent = validUrls;

			deepscanBtn.disabled = false;
			deepSpinner3.classList.add('d-none');
		});


		function formatTime(seconds) {
			const hrs = String(Math.floor(seconds / 3600)).padStart(2, '0');
			const mins = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
			const secs = String(seconds % 60).padStart(2, '0');
			return `${hrs}:${mins}:${secs}`;
		}

</script>
</body>

<!--</html>-->