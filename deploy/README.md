# Persistent coordinator deployment

The coordinator needs persistent storage and one continuously running process. This deployment serves the frontend and API together, preserving same-origin authentication and secure cookies. Container live collection describes the container host environment; it is not remote endpoint collection.

## Requirements

An Ubuntu server with Docker Compose, a domain resolving to the server, and inbound ports 80/443. Do not expose the internal API port. The application runs without root privileges. Run only one coordinator replica: SQLite and the in-process job queue are not designed for multiple replicas.

```sh
export JOCKY_DOMAIN=forensics.example.org
docker compose up --build -d
docker compose exec console cat /var/lib/jocky/data/first-login.txt
```

Open `https://forensics.example.org/#/app` and use the initial credential. The credential file is removed after first successful login. Existing credentials remain unchanged on restart. Change passwords before sharing access.

The evidence, signing key and TLS certificates use separate persistent volumes. Preserve the signing key across upgrades. Never publish volume contents or real evidence in Git. Do not run `docker compose down --volumes` against a deployment you intend to retain.

## Upgrade and recovery

```sh
docker compose up --build -d
docker compose logs --tail=100 console
```

Interrupted jobs are marked interrupted at startup; they do not silently resume. Restart a case explicitly. For consistent backups, stop the console, back up both evidence and signing-key volumes to access-controlled storage, then start the console. Test restoration before relying on backups. The health check checks API availability, not forensic completeness.

The existing Vercel URL remains a public frontend preview until a persistent host is provisioned. This configuration does not provision a paid server or domain.
