# Chronix

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

Self-hosted collaborative workspace for pentesters and red team operators. Captures notes, commands, outputs, and operational context during security engagements.

![Image of Chronix](media/image-1.png)

## Quick Start

```bash
# Install
pipx install git+https://github.com/IceCubeSandwich/chronix

# Initialize (creates account and session secret)
chronix init

# Run
chronix
```

Browser opens at `http://localhost:8000`. Credentials display once during init—store them securely.

## Features

- **Timeline Logging**: Timestamped entries with source, destination, tool, command, output, and result fields
- **Collaborative Notes**: Markdown pages with auto-save and version history
- **Real-Time Sync**: WebSocket updates across concurrent sessions
- **Filter & Search**: Filter timeline by tool, target, or text
- **CSV Export**: Export timeline for reporting workflows
- **Markdown Export**: Export notes as standalone `.md` files or zip archive with attachments
- **Image Paste**: Paste screenshots directly into notes (Ctrl+V)

## Notes Features

### Paste Images

Paste screenshots directly into the notes editor:
- **Ctrl+V** to paste from clipboard
- Supports PNG, JPEG, GIF, and WebP
- Images are stored on disk and linked via markdown
- Images render in the preview pane

### Export Notes

**Single Note Export:**
- Click the export button (↓) in the toolbar
- Select "Export current note"
- Downloads as `.md` file with YAML frontmatter

**Export All Notes:**
- Click the export button (↓) in the toolbar  
- Select "Export all notes"
- Downloads as `.zip` containing:
  - All notes as `.md` files
  - `attachments/` folder with images

Exported files open cleanly in Obsidian, VS Code, or any markdown viewer.

## Commands

```
chronix [COMMAND] [OPTIONS]

Commands:
  init          Initialize account and session secret
  serve         Start server (default)

Init Options:
  --username    Account username (default: admin)
  --force       Regenerate session secret
  --db, -d      Database file path

Server Options:
  --host, -H    Bind address (default: 0.0.0.0)
  --port, -p    Port (default: 8000)
  --local       Bind to localhost only
  --db, -d      Database file path (default: ./chronix.db)
  --no-browser  Skip automatic browser launch
```

## Deployment

### Local Use

```bash
chronix --local
```

### Production (Docker)

```bash
docker-compose up -d
```

Deploy behind a TLS-terminating reverse proxy (Caddy, Nginx). Set `CHRONIX_BEHIND_PROXY=true` for secure cookie attributes. See `Caddyfile` and `nginx.conf.example` for configurations.

## Configuration

Set via `~/.config/chronix/chronix.env` or `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `CHRONIX_SESSION_SECRET` | (required) | 64-char hex secret for cookie signing |
| `CHRONIX_DB_PATH` | `./chronix.db` | Database file location |
| `CHRONIX_ATTACHMENTS_PATH` | `./attachments` | Image attachments storage |
| `CHRONIX_MAX_ATTACHMENT_SIZE` | `10485760` | Max image size (10MB) |
| `CHRONIX_SESSION_EXPIRE_HOURS` | `24` | Session lifetime |
| `CHRONIX_BEHIND_PROXY` | `false` | Enable when behind TLS proxy |
| `CHRONIX_RATE_LIMIT_LOGIN` | `5` | Login attempts before rate limit |

## Author

**Tyrrell Brewster** — [GitHub](https://github.com/icecubesandwich) | [Website](https://0xtb.sh)

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

Source code is available at [github.com/icecubesandwich/chronix](https://github.com/icecubesandwich/chronix). Network users can also access license information via the `/license` endpoint.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting changes.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

