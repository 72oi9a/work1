<?php
declare(strict_types=1);
require_once __DIR__ . '/auth.php';

function seed_permissions(int $userId, string $role): void
{
    $pdo = db();
    $all = $role === 'قائد الفرقة';
    $defaults = $all ? array_fill_keys(PAGE_KEYS, [true, true, true, true]) : [
        'dashboard' => [true, false, false, false], 'official-forms' => [true, true, false, false],
        'members' => [true, true, true, false], 'supervisors' => [false, false, false, false],
        'reports' => [true, true, false, false], 'settings' => [false, false, false, false],
    ];
    $stmt = $pdo->prepare('INSERT INTO page_permissions (user_id,page_key,can_view,can_create,can_edit,can_delete) VALUES (:uid,:key,:view,:create,:edit,:delete) ON CONFLICT (user_id,page_key) DO UPDATE SET can_view=EXCLUDED.can_view, can_create=EXCLUDED.can_create, can_edit=EXCLUDED.can_edit, can_delete=EXCLUDED.can_delete');
    foreach ($defaults as $page => $values) $stmt->execute(['uid' => $userId, 'key' => $page, 'view' => $values[0], 'create' => $values[1], 'edit' => $values[2], 'delete' => $values[3]]);
}

function api_error(string $message, int $status): never { json_response(['error' => $message], $status); }
function path_id(string $pattern): ?int { return preg_match($pattern, parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/', $m) ? (int) $m[1] : null; }
function bool_input(mixed $value): ?bool { return is_bool($value) ? $value : (is_string($value) ? filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) : null); }

try {
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    $input = request_json();
    $pdo = db();

    if ($method === 'GET' && $path === '/api/health') {
        $pdo->query('SELECT 1'); json_response(['ok' => true, 'database' => 'connected', 'service' => 'scout-management']);
    }
    if ($path === '/api/auth/login' && $method === 'POST') {
        $username = input_string($input, 'username'); $password = (string) ($input['password'] ?? '');
        if (!$username || $password === '') api_error('أدخل اسم المستخدم وكلمة المرور', 400);
        $stmt = $pdo->prepare('SELECT id, username, full_name, role, active, password_hash FROM users WHERE username=:username');
        $stmt->execute(['username' => $username]); $user = $stmt->fetch();
        if (!$user || !$user['active'] || !verify_password($password, (string) $user['password_hash'])) api_error('بيانات الدخول غير صحيحة', 401);
        if (str_starts_with((string) $user['password_hash'], 'scrypt$')) {
            $upgrade = $pdo->prepare('UPDATE users SET password_hash=:hash, updated_at=NOW() WHERE id=:id AND password_hash=:old');
            $upgrade->execute(['hash' => password_hash_legacy($password), 'id' => $user['id'], 'old' => $user['password_hash']]);
        }
        set_session_cookie(create_session((int) $user['id']));
        json_response(['user' => current_user()]);
    }
    if ($path === '/api/auth/logout' && $method === 'POST') { logout_session(); json_response(['ok' => true]); }
    if ($path === '/api/auth/me' && $method === 'GET') json_response(['user' => require_auth()]);

    if ($path === '/api/dashboard' && $method === 'GET') {
        require_permission('dashboard');
        $stats = [
            'members' => (int) $pdo->query('SELECT COUNT(*) FROM members WHERE active=TRUE')->fetchColumn(),
            'reports' => (int) $pdo->query('SELECT COUNT(*) FROM activity_reports')->fetchColumn(),
            'patrols' => (int) $pdo->query("SELECT COUNT(DISTINCT patrol) FROM members WHERE active=TRUE AND patrol IS NOT NULL AND patrol<>''")->fetchColumn(),
            'attendance' => 92,
        ];
        $latest = $pdo->query('SELECT id,title,axis,activity_date,created_at FROM activity_reports ORDER BY activity_date DESC NULLS LAST,created_at DESC LIMIT 10')->fetchAll();
        json_response(['stats' => $stats, 'latestReports' => $latest]);
    }
    if ($path === '/api/system/monitor' && $method === 'GET') {
        require_permission('settings');
        json_response(['database' => 'connected', 'checkedAt' => $pdo->query('SELECT NOW()')->fetchColumn(), 'counts' => [
            'members' => (int) $pdo->query('SELECT COUNT(*) FROM members')->fetchColumn(), 'activities' => (int) $pdo->query('SELECT COUNT(*) FROM activity_reports')->fetchColumn(),
            'meetings' => (int) $pdo->query('SELECT COUNT(*) FROM meeting_minutes')->fetchColumn(), 'users' => (int) $pdo->query('SELECT COUNT(*) FROM users WHERE active=TRUE')->fetchColumn(),
        ]]);
    }
    if ($path === '/api/system/reset' && $method === 'POST') {
        require_permission('settings', 'delete');
        if (input_string($input, 'confirmation') !== 'تصفير') api_error('اكتب كلمة تصفير للتأكيد', 400);
        $pdo->beginTransaction();
        $deleted = ['activities' => (int) $pdo->query('DELETE FROM activity_reports')->rowCount(), 'meetings' => (int) $pdo->query('DELETE FROM meeting_minutes')->rowCount(), 'members' => (int) $pdo->query('DELETE FROM members')->rowCount()];
        $pdo->commit(); json_response(['ok' => true, 'deleted' => $deleted]);
    }

    if ($path === '/api/users' && $method === 'GET') {
        require_permission('supervisors');
        $rows = $pdo->query("SELECT u.id,u.username,u.full_name,u.role,u.active,u.created_at,COALESCE(jsonb_object_agg(p.page_key,jsonb_build_object('view',p.can_view,'create',p.can_create,'edit',p.can_edit,'delete',p.can_delete)) FILTER (WHERE p.page_key IS NOT NULL),'{}'::jsonb) AS permissions FROM users u LEFT JOIN page_permissions p ON p.user_id=u.id GROUP BY u.id ORDER BY u.created_at")->fetchAll();
        foreach ($rows as &$row) $row['permissions'] = json_decode((string) $row['permissions'], true) ?: [];
        json_response(['users' => $rows]);
    }
    if ($path === '/api/users' && $method === 'POST') {
        require_permission('supervisors', 'create');
        $username = input_string($input, 'username'); $fullName = input_string($input, 'fullName'); $role = input_string($input, 'role'); $password = (string) ($input['password'] ?? '');
        if (!$username || !$fullName || !$role || strlen($password) < 6) api_error('أكمل بيانات المستخدم، وكلمة المرور يجب أن تكون 6 أحرف على الأقل', 400);
        try { $stmt = $pdo->prepare('INSERT INTO users(username,full_name,role,password_hash) VALUES(:username,:full_name,:role,:hash) RETURNING id,username,full_name,role,active,created_at'); $stmt->execute(['username' => $username, 'full_name' => $fullName, 'role' => $role, 'hash' => password_hash_legacy($password)]); } catch (PDOException $e) { if ($e->getCode() === '23505') api_error('اسم المستخدم مستخدم مسبقاً', 409); throw $e; }
        $created = $stmt->fetch(); seed_permissions((int) $created['id'], $role); json_response(['user' => $created], 201);
    }
    $userId = path_id('#^/api/users/(\d+)(?:/permissions)?$#');
    if ($userId !== null && $method === 'PATCH') {
        require_permission('supervisors', 'edit');
        $stmt = $pdo->prepare('UPDATE users SET full_name=COALESCE(:full_name,full_name),role=COALESCE(:role,role),active=COALESCE(:active,active),updated_at=NOW() WHERE id=:id RETURNING id,username,full_name,role,active,created_at');
        $stmt->execute(['full_name' => nullable_string($input, 'fullName'), 'role' => nullable_string($input, 'role'), 'active' => bool_input($input['active'] ?? null), 'id' => $userId]); $row = $stmt->fetch();
        if (!$row) api_error('المستخدم غير موجود', 404); if (input_string($input, 'role')) seed_permissions($userId, (string) $input['role']); json_response(['user' => $row]);
    }
    if ($userId !== null && $method === 'DELETE') {
        $current = require_permission('supervisors', 'delete'); if ($userId === (int) $current['id']) api_error('لا يمكنك حذف حسابك الحالي', 400);
        $stmt = $pdo->prepare('DELETE FROM users WHERE id=:id'); $stmt->execute(['id' => $userId]); if (!$stmt->rowCount()) api_error('المستخدم غير موجود', 404); json_response(['ok' => true]);
    }
    if ($userId !== null && preg_match('#^/api/users/\d+/permissions$#', $path)) {
        $current = require_permission('supervisors', $method === 'PUT' ? 'edit' : 'view');
        if ($method === 'GET') { $stmt = $pdo->prepare('SELECT page_key,can_view,can_create,can_edit,can_delete FROM page_permissions WHERE user_id=:id ORDER BY page_key'); $stmt->execute(['id' => $userId]); json_response(['permissions' => $stmt->fetchAll()]); }
        if ($method === 'PUT') {
            $pdo->prepare('DELETE FROM page_permissions WHERE user_id=:id')->execute(['id' => $userId]);
            $stmt = $pdo->prepare('INSERT INTO page_permissions(user_id,page_key,can_view,can_create,can_edit,can_delete) VALUES(:uid,:key,:view,:create,:edit,:delete)');
            foreach (PAGE_KEYS as $page) { $item = []; foreach (($input['permissions'] ?? []) as $candidate) if (($candidate['pageKey'] ?? '') === $page) $item = $candidate; $stmt->execute(['uid' => $userId, 'key' => $page, 'view' => !empty($item['view']), 'create' => !empty($item['create']), 'edit' => !empty($item['edit']), 'delete' => !empty($item['delete'])]); }
            json_response(['ok' => true]);
        }
    }

    if ($path === '/api/members' && $method === 'GET') { require_permission('members'); json_response(['members' => $pdo->query('SELECT * FROM members ORDER BY active DESC,full_name')->fetchAll()]); }
    if ($path === '/api/members' && $method === 'POST') {
        require_permission('members', 'create'); if (!trim((string) ($input['fullName'] ?? ''))) api_error('الاسم الكامل مطلوب', 400);
        $fields = ['full_name','scout_number','national_id','birth_date','phone','guardian_name','guardian_phone','email','patrol','rank','join_date','address','medical_notes','notes']; $values = []; foreach ($fields as $field) $values[$field] = nullable_string($input, lcfirst(str_replace('_', '', ucwords($field, '_'))));
        $stmt = $pdo->prepare('INSERT INTO members('.implode(',', $fields).') VALUES('.implode(',', array_map(fn($f) => ':' . $f, $fields)).') RETURNING *'); foreach ($values as $key => $value) $stmt->bindValue(':' . $key, $value); try { $stmt->execute(); } catch (PDOException $e) { if ($e->getCode() === '23505') api_error('رقم الكشاف مستخدم مسبقاً', 409); throw $e; } json_response(['member' => $stmt->fetch()], 201);
    }
    $memberId = path_id('#^/api/members/(\d+)$#');
    if ($memberId !== null && $method === 'PATCH') {
        require_permission('members', 'edit'); $map = ['fullName'=>'full_name','scoutNumber'=>'scout_number','nationalId'=>'national_id','birthDate'=>'birth_date','phone'=>'phone','guardianName'=>'guardian_name','guardianPhone'=>'guardian_phone','email'=>'email','patrol'=>'patrol','rank'=>'rank','joinDate'=>'join_date','address'=>'address','medicalNotes'=>'medical_notes','notes'=>'notes']; $sets=[]; $params=['id'=>$memberId]; foreach($map as $key=>$field) if(array_key_exists($key,$input)){ $sets[]="$field=COALESCE(:$key,$field)"; $params[$key]=nullable_string($input,$key); } if(array_key_exists('active',$input)){ $sets[]='active=COALESCE(:active,active)'; $params['active']=bool_input($input['active']); } if (!$sets) api_error('لا توجد بيانات للتحديث',400); $sets[]='updated_at=NOW()'; $stmt=$pdo->prepare('UPDATE members SET '.implode(',',$sets).' WHERE id=:id RETURNING *'); $stmt->execute($params); if(!$row=$stmt->fetch()) api_error('العضو غير موجود',404); json_response(['member'=>$row]);
    }
    if ($memberId !== null && $method === 'DELETE') { require_permission('members','delete'); $stmt=$pdo->prepare('DELETE FROM members WHERE id=:id'); $stmt->execute(['id'=>$memberId]); if(!$stmt->rowCount()) api_error('العضو غير موجود',404); json_response(['ok'=>true]); }

    if ($path === '/api/reports' && $method === 'GET') {
        require_permission('reports'); $activity=$pdo->query("SELECT id,title,axis AS category,activity_date AS report_date,data,'activity' AS type,created_at FROM activity_reports ORDER BY activity_date DESC NULLS LAST,created_at DESC")->fetchAll(); $meetings=$pdo->query("SELECT id,title,'محضر اجتماع مجلس الشرف' AS category,meeting_date AS report_date,data,'meeting' AS type,created_at FROM meeting_minutes ORDER BY meeting_date DESC NULLS LAST,created_at DESC")->fetchAll(); $reports=array_merge($activity,$meetings); usort($reports,fn($a,$b)=>strcmp((string)($b['report_date']??$b['created_at']),(string)($a['report_date']??$a['created_at']))); json_response(['reports'=>$reports]);
    }
    if ($path === '/api/reports/activity' && $method === 'POST') { $user=require_permission('reports','create'); $title=input_string($input,'title'); $axis=input_string($input,'axis'); if(!$title||!$axis) api_error('اسم البرنامج والمحور مطلوبان',400); $stmt=$pdo->prepare('INSERT INTO activity_reports(title,axis,activity_date,data,created_by) VALUES(:title,:axis,:date,CAST(:data AS jsonb),:user) RETURNING id,title,axis,activity_date,created_at'); $stmt->execute(['title'=>$title,'axis'=>$axis,'date'=>nullable_string($input,'activityDate'),'data'=>json_encode($input['data']??[],JSON_UNESCAPED_UNICODE),'user'=>$user['id']]); json_response(['report'=>$stmt->fetch()],201); }
    if ($path === '/api/reports/meeting' && $method === 'POST') { $user=require_permission('reports','create'); $stmt=$pdo->prepare("INSERT INTO meeting_minutes(meeting_date,data,created_by) VALUES(:date,CAST(:data AS jsonb),:user) RETURNING id,title,meeting_date,created_at"); $stmt->execute(['date'=>nullable_string($input,'meetingDate'),'data'=>json_encode($input['data']??[],JSON_UNESCAPED_UNICODE),'user'=>$user['id']]); json_response(['report'=>$stmt->fetch()],201); }

    api_error('المسار غير موجود', 404);
} catch (Throwable $error) {
    error_log((string) $error);
    json_response(['error' => 'حدث خطأ غير متوقع في الخادم'], 500);
}
