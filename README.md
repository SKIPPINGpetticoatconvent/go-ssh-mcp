# SSH MCP Server

Production-ready SSH command execution server for AI agents

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP SDK](https://img.shields.io/badge/MCP-go--mcp-blue)](https://github.com/mark3labs/mcp-go)

**Connection Pooling** • **PTY Interactive Support** • **Auto-Retry & Reconnection** • **Security Guard**

[中文版](./README_zh.md)

---

## 🚀 Overview

SSH MCP Server is a production-ready [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that empowers AI agents with secure, high-performance SSH command execution capabilities on remote servers.

**The Problem:**

```
// Traditional SSH integration
- New connection for every command (slow)
- No interactive command support
- Large output crashes the buffer
- Dangerous commands can slip through
```

**The Solution:**

```
// SSH MCP Server
- Connection pooling with keepalive ⚡
- PTY support for top, htop, vim 🖥️
- Smart output truncation 📏
- Built-in command blacklisting 🛡️
- Auto-retry on broken connections 🔄
```

**Result:** Production-ready SSH execution that scales.

---

## ⚡ Key Features

### Performance
- 🚀 **Connection Pooling** - Reuse SSH connections to reduce handshake overhead
- ⚡ **Keepalive Detection** - Automatic connection health checks
- 💨 **Idle Cleanup** - Auto-close connections after 5 minutes of inactivity
- 📦 **Lightweight** - Single Go binary with minimal dependencies

### Developer Experience
- 🖥️ **PTY Support** - Interactive commands like `top`, `htop`, `vim` work seamlessly
- 🔄 **Auto-Retry** - Transparent reconnection on broken pipe or EOF errors
- 📏 **Output Truncation** - Prevents buffer overflow with smart truncation (last 2000 bytes)
- 🛡️ **Type Safe** - Full Go with static typing

### Security
- 🔒 **Command Blacklisting** - Block dangerous commands like `rm -rf /`, `mkfs`, `shutdown`
- 🔑 **Dual Authentication** - Password or private key (PEM format)
- ⚠️ **Separated Streams** - Distinct stdout/stderr for precise debugging

---

## 📦 Installation

### One-Line Install
```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/SKIPPINGpetticoatconvent/go-ssh-mcp/raw/main/tools/ssh-mcp-installer.sh | sh
```

### Build from Source

```bash
git clone https://github.com/SKIPPINGpetticoatconvent/go-ssh-mcp.git
cd go-ssh-mcp
go build -o ssh-mcp main.go
```

> Binary will be in the current directory: `./ssh-mcp`

### Go Install

```bash
go install github.com/SKIPPINGpetticoatconvent/go-ssh-mcp@latest
```

> Binary will be installed to `$GOPATH/bin/go-ssh-mcp` (typically `~/go/bin/go-ssh-mcp`)

---

## 🔧 Configuration

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "/home/your-user/go/bin/go-ssh-mcp"
    }
  }
}
```

> 💡 Use `~/go/bin/go-ssh-mcp` if installed via `go install`, or the local path if built from source

> 📍 Config file locations:
> - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
> - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
> - **Linux**: `~/.config/Claude/claude_desktop_config.json`

### VS Code

```bash
code --add-mcp '{"name":"ssh","command":"/home/your-user/go-ssh-mcp/ssh-mcp"}'
```

### Cursor

1. Open **Settings** → **MCP** → **Add new MCP Server**
2. Select **Command** type
3. Enter: `/home/your-user/go-ssh-mcp/ssh-mcp`

### Windsurf / Cline

Add to your MCP config:

```json
{
  "mcpServers": {
    "ssh": {
      "command": "/home/your-user/go-ssh-mcp/ssh-mcp"
    }
  }
}
```

---

## 🎯 Quick Start

### Basic Command Execution

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "password": "your-password",
  "command": "uname -a"
}
```

**Result:**
```
Linux server 5.15.0-generic #1 SMP x86_64 GNU/Linux
```

### Using Private Key Authentication

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "command": "whoami"
}
```

### Interactive Commands with PTY

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "password": "your-password",
  "command": "top -bn1",
  "usePty": true
}
```

### Execute in Specific Directory

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "password": "your-password",
  "command": "ls -la",
  "workingDir": "/var/log"
}
```

### Upload File to Remote Server

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "password": "your-password",
  "localPath": "/home/user/config.json",
  "remotePath": "/etc/app/config.json",
  "overwrite": true
}
```

### Download File from Remote Server

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "password": "your-password",
  "remotePath": "/var/log/app.log",
  "localPath": "/tmp/app.log"
}
```

### Upload Base64 Content

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "password": "your-password",
  "content": "SGVsbG8gV29ybGQh",
  "remotePath": "/tmp/hello.txt"
}
```

---

## 📖 API Reference

### `ssh_execute` Tool

Execute commands on remote servers via SSH.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | ✅ | Remote host address (e.g., `192.168.1.100`) |
| `port` | string | ✅ | SSH port (default: `22`) |
| `user` | string | ✅ | Remote username |
| `password` | string | ❌ | SSH password (optional if using private key) |
| `privateKey` | string | ❌ | SSH private key content (PEM format) |
| `command` | string | ✅ | Command to execute |
| `workingDir` | string | ❌ | Working directory for the command |
| `usePty` | boolean | ❌ | Enable PTY for interactive commands |

---

### `scp_upload` Tool

Upload files to remote servers via SFTP protocol.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | ✅ | Remote host address |
| `port` | string | ✅ | SSH port (default: `22`) |
| `user` | string | ✅ | Remote username |
| `password` | string | ❌ | SSH password |
| `privateKey` | string | ❌ | SSH private key (PEM format) |
| `localPath` | string | ❌ | Local file path (one of `localPath` or `content` required) |
| `content` | string | ❌ | Base64-encoded file content |
| `remotePath` | string | ✅ | Remote destination path |
| `overwrite` | boolean | ❌ | Overwrite existing file (default: `false`) |

---

### `scp_download` Tool

Download files from remote servers via SFTP protocol.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host` | string | ✅ | Remote host address |
| `port` | string | ✅ | SSH port (default: `22`) |
| `user` | string | ✅ | Remote username |
| `password` | string | ❌ | SSH password |
| `privateKey` | string | ❌ | SSH private key (PEM format) |
| `remotePath` | string | ✅ | Remote file path |
| `localPath` | string | ❌ | Local save path (optional, returns Base64 if not provided) |
| `maxSize` | number | ❌ | Maximum download size in bytes (default: 10MB) |

> ⚠️ **Note:** Either `password` or `privateKey` must be provided for all tools.

---

## 🛡️ Security Features

### Command Blacklisting

The following dangerous commands are blocked by default:

| Blocked Pattern | Risk Level | Description |
|-----------------|------------|-------------|
| `rm -rf /` | 🔴 Critical | Recursive deletion of root |
| `rm -rf *` | 🔴 Critical | Recursive deletion of current directory |
| `mkfs` | 🔴 Critical | Filesystem formatting |
| `shutdown` | 🟠 High | System shutdown |
| `reboot` | 🟠 High | System reboot |
| `init 0` / `init 6` | 🟠 High | Runlevel changes |
| `dd if=` | 🟠 High | Raw disk operations |
| `:(){ :|:& };:` | 🔴 Critical | Fork bomb |

### Best Practices

1. **Use Private Keys** - More secure than passwords
2. **Limit User Permissions** - Create dedicated SSH users with minimal privileges
3. **Network Isolation** - Run MCP server in a trusted network environment
4. **Host Key Verification** - Configure proper host key checking in production

---

## 🏗️ Architecture

### Tech Stack

| Component | Technology |
|-----------|------------|
| Runtime | Go 1.22+ |
| MCP SDK | [mcp-go](https://github.com/mark3labs/mcp-go) |
| SSH Library | [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) |
| Protocol | Model Context Protocol (MCP) |
| Transport | stdio |

### Connection Pool Design

```
┌─────────────────────────────────────────────────┐
│                 SSH MCP Server                  │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────┐    ┌─────────────────────┐    │
│  │ MCP Handler │───▶│   Connection Pool   │    │
│  └─────────────┘    ├─────────────────────┤    │
│                     │ user@host:port → conn│    │
│                     │ user@host:port → conn│    │
│                     └─────────────────────┘    │
│                              │                  │
│                     ┌────────▼────────┐        │
│                     │  Idle Cleanup   │        │
│                     │  (every 1 min)  │        │
│                     │  TTL: 5 minutes │        │
│                     └─────────────────┘        │
│                                                 │
└─────────────────────────────────────────────────┘
```

### Design Principles

- 🔒 **Security First** - Command blacklisting, structured error handling
- ⚡ **Performance** - Connection pooling, keepalive detection
- 🛡️ **Reliability** - Auto-retry, graceful error recovery
- 🎯 **Simplicity** - Single tool, clear API

---

## 🔧 Troubleshooting

### "Either password or privateKey must be provided"

**Cause:** Neither authentication method was specified.

**Solution:** Provide either `password` or `privateKey` in your request.

### "Failed to parse private key"

**Cause:** Invalid private key format.

**Solution:**
- Ensure the key is in PEM format
- Include the full key content with headers (`-----BEGIN ... -----`)
- Check for extra whitespace or encoding issues

### "SECURITY_ERROR: The command contains restricted pattern"

**Cause:** Command matches a blacklisted pattern.

**Solution:**
- Review and modify your command to avoid dangerous patterns
- If legitimate use, consider modifying the blacklist in `main.go`

### Connection Timeout

**Cause:** Network issues or firewall blocking.

**Solution:**
- Verify host and port are correct
- Check firewall rules
- Ensure SSH service is running on the remote host

---

## 🗺️ Roadmap

### ✅ Completed
- [x] Connection pooling with keepalive
- [x] PTY support for interactive commands
- [x] Auto-retry on connection failure
- [x] Output truncation for large files
- [x] Command blacklisting
- [x] Dual authentication (password/key)
- [x] Working directory support
- [x] **SCP/SFTP file upload/download**

### 🚀 Planned
- [ ] Port forwarding (tunneling)
- [ ] Multi-hop SSH (jump hosts)
- [ ] Custom timeout configuration
- [ ] Host key verification
- [ ] Session multiplexing
- [ ] Execute scripts from files

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

[MIT](LICENSE) © SSH MCP Server Contributors

---

## 🙏 Credits

Built with:

- [mcp-go](https://github.com/mark3labs/mcp-go) - Go MCP SDK
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - Go cryptography libraries
- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol specification

---

<p align="center">
  <b>Connection Pooling</b> • <b>PTY Support</b> • <b>Auto-Retry</b> • <b>Security Guard</b>
</p>
