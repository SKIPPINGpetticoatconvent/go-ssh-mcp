# SSH MCP Server

[中文版](./README_zh.md)

An implementation of the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that provides secure SSH command execution capabilities.

## Features

- **Connection Pooling**: Reuses SSH connections to reduce handshake overhead and improve performance.
- **PTY (Pseudo-Terminal) Support**: Supports interactive commands like `top`, `htop`, and `vim` by requesting a pseudo-terminal.
- **Auto-Retry & Reconnection**: Automatically detects broken connections and attempts to reconnect once before failing.
- **Output Truncation**: Prevents large outputs (e.g., massive log files) from overflowing the MCP buffer by showing only the last 2000 bytes.
- **Security Guard**: Built-in command blacklisting to prevent execution of dangerous commands (e.g., `rm -rf /`).
- **Structured Error Handling**: Separates `stdout` and `stderr` for clearer debugging.
- **Authentication**: Supports both password and private key authentication.

## Installation

```bash
go build -o ssh-mcp main.go
```

## Usage

Register the server in your MCP client (e.g., Claude Desktop) with the following configuration:

### Configuration Parameters

The `ssh_execute` tool accepts the following parameters:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `host` | Yes | Remote host address (e.g., `127.0.0.1`) |
| `port` | Yes | SSH port (default is `22`) |
| `user` | Yes | Remote username |
| `password`| No | SSH password (optional if using private key) |
| `privateKey`| No | SSH private key content (PEM format) |
| `command` | Yes | Command to execute |
| `workingDir`| No | Working directory for the command |
| `usePty` | No | Whether to enable PTY for interactive commands |

## License

MIT
