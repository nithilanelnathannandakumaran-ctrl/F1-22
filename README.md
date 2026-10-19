# F1 22 on Cloudflare (accounts + admin panel)

Players: `https://<your-site>/`   Admin panel: `https://<your-site>/admin.html`

## Deploy (about 5 minutes)
You need Node.js and a free Cloudflare account.

    cd f1-cloudflare
    npm i -g wrangler
    wrangler login
    wrangler d1 create f1-22            # copy the database_id it prints into wrangler.toml
    wrangler d1 execute f1-22 --remote --file=schema.sql
    wrangler secret put ADMIN_PASSWORD  # choose a long admin password
    wrangler deploy

Wrangler prints your `https://f1-22.<you>.workers.dev` address.
Local test: `wrangler d1 execute f1-22 --local --file=schema.sql` then `wrangler dev`
(put `ADMIN_PASSWORD=test` in a `.dev.vars` file).

## Admin panel
Sign in to the game with username **elnathan** and your ADMIN_PASSWORD (the account is created on first sign-in, the name is reserved
so nobody else can register it). An "admin panel" link then appears in the menu. `/admin.html` also accepts the password directly.
To use another name, set `ADMIN_USERNAME` in wrangler.toml under `[vars]`.

Rename (login name + in-game driver name), ban for 1h / 24h / 7d / 30d / permanent with a reason the player sees,
unban, force log out, reset password, reset best laps, delete account, close/open sign-ups, log everyone out,
search, live stats and an activity log. Banned players are kicked to the login screen within ~45 seconds.

## Notes
- Passwords are salted PBKDF2 hashes, sessions are HttpOnly cookies, login and admin attempts are rate-limited.
- Keep the admin URL and password private. Changing ADMIN_PASSWORD signs all admins out.
- Player profiles (driver name/number, livery, best laps per track) are saved to the account.
