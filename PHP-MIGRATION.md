# PHP migration

The PHP entry point is now the production web path. The existing Node files are intentionally retained so the Node service can be used during cutover or rollback.

## Requirements

- PHP 8.1 or newer with `pdo_pgsql`, `json`, and `hash` enabled.
- Apache with `mod_rewrite` and `AllowOverride FileInfo AuthConfig` for this directory, or equivalent web-server rewrites.
- PostgreSQL and `DATABASE_URL` in `.env` or the process environment.

Run `schema.sql` against the target PostgreSQL database before the first PHP request. The PHP API uses the same tables and JSON response shapes as the Node API.

## Routes

Clean routes such as `/login`, `/dashboard`, `/forms`, `/reports`, `/members`, `/supervisors`, and `/settings` are served by self-contained PHP entry points. `/forms-generator` is also self-contained PHP and keeps activity/meeting submission, QR preview, and browser print/PDF behavior. Old `.html` URLs redirect to their clean PHP routes for bookmark compatibility.

The direct PHP API is in `php/api.php`; `php/auth.php` owns sessions, RBAC, and the legacy password verifier. Internal helper files are denied by `.htaccess`.

## Password migration

On a successful login, a Node-format `scrypt$<salt>$<hex>` password is verified using the compatible scrypt parameters and immediately replaced with a newly generated scrypt hash. The update is conditional on the old hash, so concurrent logins cannot overwrite a newer password. No plaintext password is stored.

## Cutover checklist

1. Install the PHP extensions and import `schema.sql`.
2. Set `DATABASE_URL` and use HTTPS in production so the session cookie is secure.
3. Point Apache (or the equivalent PHP front controller) at this directory.
4. Test `/api/health`, login, each permitted page, report creation, and logout.
5. Keep the Node service available until PHP login and report flows have been confirmed against the production database.

PHP is not installed in the current development environment, so `php -l` and a live PDO/login test could not be performed here. Static checks confirmed that PHP page entrypoints do not read `.html` templates, route parity is retained, and the existing Node app and HTML assets were not removed.