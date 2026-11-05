<?php
/* Legal Agenda API - Server-first login + MySQL snapshot sync (PHP 7.4+) */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Vary: Origin');

$origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');
$hostHeader = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));

// Exact allowlist for Android WebView assets plus same-host web access.
// Credentialed CORS must use an explicit origin, never "*".
$allowedOrigins = ['https://appassets.androidplatform.net', 'null', 'http://localhost:8000', 'http://127.0.0.1:8000'];
$originHost = strtolower((string)(parse_url($origin, PHP_URL_HOST) ?? ''));
$requestHost = preg_replace('/:\d+$/', '', $hostHeader);
$isSameHost = ($originHost !== '' && $originHost === $requestHost);
if (($origin !== '' && (in_array($origin, $allowedOrigins, true) || $isSameHost))) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
}
header('Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS');
header('Access-Control-Allow-Headers: Accept, Content-Type, X-API-Key, Authorization');
header('Access-Control-Max-Age: 600');

function reply(int $status, array $body): void {
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function password_hash_agenda(string $password, string $salt): string {
    $x = $salt . ':' . $password;
    for ($i = 0; $i < 2000; $i++) $x = hash('sha256', $x . $salt);
    return $x;
}

function is_admin_user(?array $user): bool {
    if (!$user) return false;
    return in_array(strtolower((string)($user['role'] ?? 'user')), ['admin','administrator','مدير'], true);
}
function role_filtered_data(array $data, array $user): array {
    if (is_admin_user($user)) return $data;
    $role = (string)($user['role'] ?? 'user');
    $visibility = $data['settings']['sectionVisibility'][$role] ?? [];
    $sectionMap = [
        'agenda'=>['sessions','tasks'], 'calendar'=>['sessions','tasks'],
        'poa'=>['poas'], 'deadlines'=>['deadlines'], 'records'=>['clients','cases'],
        'courts'=>['courts'], 'gov'=>['portals']
    ];
    foreach ($sectionMap as $section=>$keys) {
        if (isset($visibility[$section]) && $visibility[$section] === false) {
            foreach ($keys as $key) $data[$key] = [];
        }
    }
    // Never expose the full user directory or the administrator announcement to ordinary users.
    $uid = (string)($user['id'] ?? '');
    $data['users'] = array_values(array_filter($data['users'] ?? [], function($u) use ($uid) {
        return is_array($u) && (string)($u['id'] ?? '') === $uid;
    }));
    unset($data['banner']);
    return $data;
}
function merge_role_data(array $old, array $incoming, array $user): array {
    if (is_admin_user($user)) return $incoming;
    $role = (string)($user['role'] ?? 'user');
    $visibility = $old['settings']['sectionVisibility'][$role] ?? [];
    $sectionMap = [
        'agenda'=>['sessions','tasks'], 'calendar'=>['sessions','tasks'],
        'poa'=>['poas'], 'deadlines'=>['deadlines'], 'records'=>['clients','cases'],
        'courts'=>['courts'], 'gov'=>['portals']
    ];
    foreach ($sectionMap as $section=>$keys) {
        if (isset($visibility[$section]) && $visibility[$section] === false) {
            foreach ($keys as $key) $incoming[$key] = $old[$key] ?? [];
        }
    }
    // User-role clients cannot modify accounts, role visibility policy, or announcements.
    $incoming['users'] = $old['users'] ?? [];
    $incoming['banner'] = $old['banner'] ?? null;
    if (!isset($incoming['settings']) || !is_array($incoming['settings'])) $incoming['settings'] = [];
    if (!isset($incoming['settings']['sectionVisibility']) && isset($old['settings']['sectionVisibility'])) {
        $incoming['settings']['sectionVisibility'] = $old['settings']['sectionVisibility'];
    } else if (isset($old['settings']['sectionVisibility'])) {
        $incoming['settings']['sectionVisibility'] = $old['settings']['sectionVisibility'];
    }
    return $incoming;
}

function clean_data(array $data): array {
    if (isset($data['settings']) && is_array($data['settings'])) unset($data['settings']['cred']);
    if (isset($data['ocr']) && is_array($data['ocr'])) {
        if (isset($data['ocr']['gemini']) && is_array($data['ocr']['gemini'])) unset($data['ocr']['gemini']['key']);
        if (isset($data['ocr']['space']) && is_array($data['ocr']['space'])) unset($data['ocr']['space']['key']);
    }
    return $data;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') { http_response_code(204); exit; }
if (!in_array(($_SERVER['REQUEST_METHOD'] ?? ''), ['GET','POST','PUT'], true)) reply(405, ['success'=>false,'message'=>'Method not allowed']);
if (!is_file(__DIR__ . '/config.php')) reply(503, ['success'=>false,'message'=>'لم يتم تثبيت النظام بعد.']);

define('LEGAL_AGENDA_BOOTSTRAP', true);
$cfg = require __DIR__ . '/config.php';
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name('LEGAL_AGENDA_SESSID');
    // API is served over HTTPS; SameSite=None is required for cross-origin
    // Android WebView requests that use fetch(..., credentials: 'include').
    session_set_cookie_params([
        'lifetime' => 60 * 60 * 24 * 30,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'None'
    ]);
    session_start();
}

$collections = ['clients','cases','poas','sessions','tasks','deadlines','users','courts','portals','inquiries','bailiffs','fired'];
function ensure_schema(PDO $pdo, array $collections): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS legal_agenda_data (id TINYINT UNSIGNED NOT NULL PRIMARY KEY, payload LONGTEXT NULL, revision BIGINT UNSIGNED NOT NULL DEFAULT 0, updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    $pdo->exec("INSERT IGNORE INTO legal_agenda_data (id,payload,revision) VALUES (1,NULL,0)");
    foreach ($collections as $name) {
        $table = 'legal_agenda_' . $name;
        $pdo->exec("CREATE TABLE IF NOT EXISTS `$table` (record_id VARCHAR(191) NOT NULL PRIMARY KEY, data_json LONGTEXT NOT NULL, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }
    $pdo->exec("CREATE TABLE IF NOT EXISTS legal_agenda_settings (setting_key VARCHAR(100) NOT NULL PRIMARY KEY, data_json LONGTEXT NOT NULL, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}
function mirror_data(PDO $pdo, array $data, array $collections): array {
    $counts = [];
    foreach ($collections as $name) {
        $table = 'legal_agenda_' . $name;
        $items = $data[$name] ?? [];
        if (!is_array($items)) $items = [];
        $pdo->exec("DELETE FROM `$table`");
        $insert = $pdo->prepare("INSERT INTO `$table` (record_id,data_json) VALUES (:id,:json)");
        $count = 0;
        foreach ($items as $index => $item) {
            $id = (is_array($item) && isset($item['id']) && is_scalar($item['id'])) ? (string)$item['id'] : (string)$index;
            if ($id === '') $id = (string)$index;
            $json = json_encode($item, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($json === false) throw new RuntimeException('تعذر تحويل سجل ' . $name . ' إلى JSON');
            $insert->execute([':id'=>$id, ':json'=>$json]);
            $count++;
        }
        $counts[$name] = $count;
    }
    $pdo->exec('DELETE FROM legal_agenda_settings');
    $settings = [];
    foreach ($data as $key => $value) if (!in_array($key, $collections, true)) $settings[$key] = $value;
    $insert = $pdo->prepare('INSERT INTO legal_agenda_settings (setting_key,data_json) VALUES (:k,:v)');
    foreach ($settings as $key => $value) {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json !== false) $insert->execute([':k'=>(string)$key, ':v'=>$json]);
    }
    $counts['settings'] = count($settings);
    return $counts;
}

try {
    $pdo = new PDO(
        'mysql:host=' . $cfg['db_host'] . ';dbname=' . $cfg['db_name'] . ';charset=utf8mb4',
        $cfg['db_user'], $cfg['db_pass'],
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES=>false, PDO::ATTR_TIMEOUT=>10]
    );
    ensure_schema($pdo, $collections);
    $method = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $raw = file_get_contents('php://input');
    $body = json_decode($raw ?: '', true);
    if (!is_array($body)) $body = [];

    $row = $pdo->query('SELECT payload, revision, updated_at FROM legal_agenda_data WHERE id=1')->fetch();
    if (!$row) reply(500, ['success'=>false,'message'=>'سجل قاعدة البيانات غير موجود.']);
    $data = null;
    if ($row['payload'] !== null) {
        $data = json_decode((string)$row['payload'], true);
        if (!is_array($data)) reply(500, ['success'=>false,'message'=>'بيانات السيرفر تالفة أو غير صالحة.']);
    }
    $users = (is_array($data) && isset($data['users']) && is_array($data['users'])) ? $data['users'] : [];

    // Server-first login: authenticate against the users stored in the current MySQL snapshot.
    if ($method === 'POST' && ($body['action'] ?? '') === 'login') {
        if (!$users) reply(409, ['success'=>false,'message'=>'لا توجد حسابات محفوظة على السيرفر. افتح الجهاز الأساسي وارفع بياناته أولًا.']);
        $username = strtolower(trim((string)($body['username'] ?? '')));
        $password = (string)($body['password'] ?? '');
        $found = null;
        foreach ($users as $user) {
            if (is_array($user) && strtolower((string)($user['username'] ?? '')) === $username) { $found = $user; break; }
        }
        if (!$found || empty($found['active']) || !isset($found['salt'],$found['hash']) || !hash_equals((string)$found['hash'], password_hash_agenda($password, (string)$found['salt']))) {
            reply(401, ['success'=>false,'message'=>'اسم المستخدم أو كلمة المرور غير صحيحة']);
        }
        session_regenerate_id(true);
        $_SESSION['legal_agenda_uid'] = (string)($found['id'] ?? '');
        $_SESSION['legal_agenda_login'] = time();
        reply(200, ['success'=>true,'user'=>['id'=>$found['id'],'username'=>$found['username'],'name'=>$found['name']??'','role'=>$found['role']??'user','dflt'=>!empty($found['dflt'])], 'data'=>role_filtered_data($data, $found), 'revision'=>(int)$row['revision'], 'updated_at'=>$row['updated_at']]);
    }
    if ($method === 'POST' && ($body['action'] ?? '') === 'logout') {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires' => time() - 42000,
                'path' => $params['path'] ?? '/',
                'domain' => $params['domain'] ?? '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None'
            ]);
        }
        session_destroy();
        reply(200, ['success'=>true,'message'=>'تم تسجيل الخروج']);
    }

    $sessionUid = (string)($_SESSION['legal_agenda_uid'] ?? '');
    $sessionUser = null;
    if ($sessionUid !== '') {
        foreach ($users as $user) if (is_array($user) && (string)($user['id'] ?? '') === $sessionUid && !empty($user['active'])) { $sessionUser = $user; break; }
    }
    $sessionOk = $sessionUser !== null;
    if (!$sessionOk) reply(401, ['success'=>false,'message'=>'يلزم تسجيل الدخول للوصول إلى بيانات الأجندة.']);

    if ($method === 'GET') {
        if (($_GET['meta'] ?? '') === '1') reply(200, ['success'=>true,'revision'=>(int)$row['revision'],'updated_at'=>$row['updated_at']]);
        reply(200, ['success'=>true,'data'=>role_filtered_data($data, $sessionUser),'user_id'=>$sessionUid,'user'=>$sessionUser,'revision'=>(int)$row['revision'],'updated_at'=>$row['updated_at']]);
    }

    if ($method === 'PUT') {
        if (!isset($body['data']) || !is_array($body['data'])) reply(400, ['success'=>false,'message'=>'صيغة البيانات غير صحيحة.']);
        $newData = merge_role_data(is_array($data) ? $data : [], $body['data'], $sessionUser);
        $newData = clean_data($newData);
        $payload = json_encode($newData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($payload === false) reply(400, ['success'=>false,'message'=>'تعذر تحويل البيانات إلى JSON.']);
        if (!array_key_exists('expected_revision', $body)) reply(409, ['success'=>false,'message'=>'نسخة المزامنة غير محددة؛ حمّل بيانات السيرفر أولًا.']);
        $pdo->beginTransaction();
        $locked = $pdo->query('SELECT revision FROM legal_agenda_data WHERE id=1 FOR UPDATE')->fetch();
        $current = (int)($locked['revision'] ?? 0);
        $expected = is_numeric($body['expected_revision']) ? (int)$body['expected_revision'] : -1;
        if ($expected !== $current) {
            $pdo->rollBack();
            reply(409, ['success'=>false,'code'=>'revision_conflict','revision'=>$current,'message'=>'توجد نسخة أحدث على السيرفر. حمّل نسخة السيرفر أو راجع التعارض قبل الرفع.']);
        }
        $counts = mirror_data($pdo, $newData, $collections);
        $next = $current + 1;
        $update = $pdo->prepare('UPDATE legal_agenda_data SET payload=:payload, revision=:revision, updated_at=CURRENT_TIMESTAMP WHERE id=1');
        $update->execute([':payload'=>$payload, ':revision'=>$next]);
        $pdo->commit();
        reply(200, ['success'=>true,'revision'=>$next,'tables'=>$counts,'message'=>'تم تحديث بيانات السيرفر بنجاح.']);
    }
    reply(405, ['success'=>false,'message'=>'Method not allowed']);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
    error_log('Legal Agenda Server-first API: ' . $e->getMessage());
    reply(500, ['success'=>false,'message'=>'حدث خطأ داخلي في خدمة البيانات. راجع سجل أخطاء PHP.']);
}
