<?php
require_once __DIR__ . '/php/auth.php';
if (current_user()) { header('Location: /dashboard', true, 302); exit; }
?>
<!doctype html>
<html lang="ar" dir="rtl">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>تسجيل الدخول | فرقة متقدم النعيم</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/app.css"></head>
<body class="login-page"><main class="login-card"><img class="login-logo" src="/attached_assets/image_1789389348245.png" alt="شعار الفرقة"><p class="eyebrow">منظومة الإدارة والتقارير</p><h1>تسجيل الدخول</h1><p class="muted">فرقة متقدم النعيم الكشفية</p><form id="login-form" class="stack"><label>اسم المستخدم أو البريد<input id="username" required autocomplete="username" value="al-naaim_scout"></label><label>كلمة المرور<input id="password" type="password" required autocomplete="current-password" value="scout2026"></label><button class="button primary" type="submit">دخول</button><p id="login-error" class="error" hidden></p></form></main>
<script>
const form=document.getElementById("login-form"),error=document.getElementById("login-error");form.addEventListener("submit",async(event)=>{event.preventDefault();error.hidden=true;const response=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",body:JSON.stringify({username:document.getElementById("username").value.trim(),password:document.getElementById("password").value})});const payload=await response.json().catch(()=>({}));if(!response.ok){error.textContent=payload.error||"بيانات الدخول غير صحيحة";error.hidden=false;return;}window.location.href="/dashboard";});
</script></body></html>
