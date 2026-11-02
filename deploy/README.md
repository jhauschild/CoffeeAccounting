# Deploy notes

Production runs the published image **`ghcr.io/jhauschild/coffeeaccounting`**
([package page](https://github.com/jhauschild/CoffeeAccounting/pkgs/container/coffeeaccounting)).
`docker-compose.yml` pulls `:latest` (or pin a digest / git-sha tag); do not `docker compose build` on the server.
Keep a checkout only for Compose, `.env`, and these proxy examples.

## Keep one-time tokens out of the logs

`/verify/<token>` (member confirmation 24 h, guest approval 7 days) and `/reset/<token>` (password
reset, 1 h) carry a single-use secret in the URL. Anyone who can read a log line with a still-valid token
can use it, which defeats the hash-only storage of tokens in the database.

* The application container starts uvicorn with `--no-access-log` (`scripts/run.sh`) and logs each request
  itself as `METHOD /verify/<redacted> -> STATUS` (logger `app.access`, `app/web/accesslog.py`).
* The reverse proxy must redact the same two prefixes, in the request URI and in the `Referer` header
  (the browser sends the full page URL as Referer for the page's own static files):
  the examples in `Caddyfile` (`log` / `format filter`) and `nginx.conf` (`map` + `log_format coffee`)
  do this. Other proxies, CDNs and load balancers need the equivalent setting.
* nginx also prints the request line in its error log on upstream errors; the example sets
  `error_log ... crit`.
