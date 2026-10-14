# ecomsec im Container

Das Image enthält nur das statisch gebaute `ecomsec`-Binary auf
[distroless/static](https://github.com/GoogleContainerTools/distroless) – keine Shell,
kein Paketmanager, läuft als unprivilegierter Benutzer (UID 65532).

| Pfad | Zweck |
|---|---|
| `/shop` | Shop-Verzeichnis – **immer read-only** einhängen (`:ro`) |
| `/state` | Zustand: Akzeptanzen, Baseline, Verlauf, letzter Report (`ECOMSEC_STATE_DIR`) |

```bash
# Image holen (oder lokal bauen: docker build -t ecomsec .)
docker pull ghcr.io/liohtml/ecom-sec:latest

# Scan (Dateisystem; Shop read-only, Zustand in einem benannten Volume)
docker run --rm \
  -v /var/www/shop:/shop:ro \
  -v ecomsec-state:/state \
  ghcr.io/liohtml/ecom-sec:latest scan --skip-remote

# Mit Datenbank-Prüfungen: der Container muss die Shop-Datenbank erreichen
# (z. B. --network host oder dasselbe Docker-Netz wie die Datenbank)
docker run --rm --network host \
  -v /var/www/shop:/shop:ro -v ecomsec-state:/state \
  ghcr.io/liohtml/ecom-sec:latest scan

# Bericht als SARIF/HTML ins aktuelle Verzeichnis schreiben
docker run --rm -v /var/www/shop:/shop:ro -v ecomsec-state:/state -v "$PWD:/out" \
  ghcr.io/liohtml/ecom-sec:latest scan --skip-remote --format sarif --output /out/ecomsec.sarif

# Dashboard (im Container auf 0.0.0.0 binden – dann immer mit Token!)
# Aufruf: http://127.0.0.1:8787/?token=<TOKEN>
TOKEN="$(openssl rand -hex 16)"; echo "Token: $TOKEN"
docker run --rm -p 127.0.0.1:8787:8787 \
  -v /var/www/shop:/shop:ro -v ecomsec-state:/state \
  ghcr.io/liohtml/ecom-sec:latest serve --bind 0.0.0.0:8787 --auth-token "$TOKEN"
```

## Docker Compose

Die Datei [`docker-compose.yml`](../docker-compose.yml) im Repository enthält drei fertige Dienste:

| Dienst | Aufruf | Zweck |
|---|---|---|
| `scan` | `docker compose run --rm scan` | einmaliger Scan, HTML-Bericht nach `./reports/ecomsec.html` |
| `dashboard` | `docker compose up -d dashboard` | Web-Dashboard auf `http://127.0.0.1:8787/?token=…` |
| `watch` | `docker compose up -d watch` | tägliche Überwachung mit Benachrichtigung (Kanäle in `ecomsec.toml`) |

```bash
printf 'SHOP_DIR=/var/www/shop\nECOMSEC_TOKEN=%s\n' "$(openssl rand -hex 16)" > .env
docker compose run --rm scan
docker compose up -d dashboard
```

Image-Tags: `latest` (letztes stabiles Release), `0.1` (Minor-Linie), `0.1.0` (exakte Version).
Das Image gibt es für `linux/amd64` und `linux/arm64`; `docker pull` wählt automatisch die passende Variante.

Hinweise:

* Arbeitsverzeichnis ist `/shop`, `--root` kann daher entfallen.
* Der Container läuft als UID 65532. Sind Shop-Dateien (z. B. `config.JTL-Shop.ini.php` mit `0600`)
  nur für den Webserver-Benutzer lesbar, mit dessen Kennung starten: `--user "$(stat -c %u:%g /var/www/shop)"` –
  `/state` dann als Host-Verzeichnis mit passenden Rechten einhängen.
* Das Ausgabeverzeichnis (`/out` im Beispiel) muss für UID 65532 beschreibbar sein.
* `ecomsec self-update` ist im Container nicht sinnvoll – stattdessen das Image aktualisieren
  (`docker pull …`). Tags: `latest`, `X.Y`, `X.Y.Z`.
* Shopify benötigt keinen Mount: `docker run --rm -e SHOPIFY_ACCESS_TOKEN=shpat_… ghcr.io/liohtml/ecom-sec scan --platform shopify --shop mein-shop.myshopify.com`.
