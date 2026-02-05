# SSH MCP 服务端

面向 AI 智能体的生产级 SSH 命令执行服务

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP SDK](https://img.shields.io/badge/MCP-go--mcp-blue)](https://github.com/mark3labs/mcp-go)

**连接池管理** • **PTY 交互支持** • **自动重连** • **安全卫士**

[English Version](./README.md)

---

## 🚀 项目概述

SSH MCP Server 是一个生产就绪的 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 服务端，为 AI 智能体提供安全、高性能的远程 SSH 命令执行能力。

**传统方案的问题：**

```
// 传统 SSH 集成方式
- 每个命令都建立新连接 (慢)
- 不支持交互式命令
- 大输出会撑爆缓冲区
- 危险命令无法拦截
```

**SSH MCP Server 的解决方案：**

```
// SSH MCP Server
- 连接池 + Keepalive 保活 ⚡
- PTY 支持 top, htop, vim 🖥️
- 智能输出截断 📏
- 内置命令黑名单 🛡️
- 断线自动重试 🔄
```

**结果：** 生产就绪的 SSH 执行方案，轻松应对高并发场景。

---

## ⚡ 核心特性

### 性能优化
- 🚀 **连接池管理** - 复用 SSH 连接，减少握手开销
- ⚡ **Keepalive 检测** - 自动检测连接健康状态
- 💨 **空闲清理** - 5 分钟不活跃自动关闭连接
- 📦 **轻量级** - 单一 Go 二进制文件，依赖极少

### 开发体验
- 🖥️ **PTY 支持** - 完美支持 `top`, `htop`, `vim` 等交互式命令
- 🔄 **自动重试** - 遇到断开连接透明重试
- 📏 **输出截断** - 智能截断防止缓冲区溢出 (保留最后 2000 字节)
- 🛡️ **类型安全** - 完整的 Go 静态类型

### 安全保障
- 🔒 **命令黑名单** - 拦截 `rm -rf /`、`mkfs`、`shutdown` 等危险命令
- 🔑 **双重认证** - 支持密码或私钥 (PEM 格式)
- ⚠️ **流分离** - stdout/stderr 分开捕获，精准定位问题

---

## 📦 安装

### 从源码编译

```bash
go build -o ssh-mcp main.go
```

> 二进制文件将生成在当前目录：`./ssh-mcp`

### Go Install

```bash
go install github.com/SKIPPINGpetticoatconvent/go-ssh-mcp@latest
```

> 二进制文件将安装到 `$GOPATH/bin/go-ssh-mcp` (默认为 `~/go/bin/go-ssh-mcp`)

---

## 🔧 配置

### Claude Desktop

添加到 `claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "/home/your-user/go/bin/go-ssh-mcp"
    }
  }
}
```

> 💡 如通过 `go install` 安装使用 `~/go/bin/go-ssh-mcp`，如从源码编译则使用本地路径

> 📍 配置文件位置：
> - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
> - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
> - **Linux**: `~/.config/Claude/claude_desktop_config.json`

### VS Code

```bash
code --add-mcp '{"name":"ssh","command":"/home/your-user/go-ssh-mcp/ssh-mcp"}'
```

### Cursor

1. 打开 **Settings** → **MCP** → **Add new MCP Server**
2. 选择 **Command** 类型
3. 输入: `/home/your-user/go-ssh-mcp/ssh-mcp`

### Windsurf / Cline

添加到 MCP 配置文件：

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

## 🎯 快速开始

### 基础命令执行

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "password": "your-password",
  "command": "uname -a"
}
```

**返回结果：**
```
Linux server 5.15.0-generic #1 SMP x86_64 GNU/Linux
```

### 使用私钥认证

```json
{
  "host": "192.168.1.100",
  "port": "22",
  "user": "admin",
  "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "command": "whoami"
}
```

### 交互式命令 (启用 PTY)

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

### 指定工作目录

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

### 上传文件到远程服务器

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

### 从远程服务器下载文件

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

### 上传 Base64 内容

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

## 📖 API 参考

### `ssh_execute` 工具

通过 SSH 在远程服务器上执行命令。

#### 参数说明

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| `host` | string | ✅ | 远程主机地址 (例如: `192.168.1.100`) |
| `port` | string | ✅ | SSH 端口 (默认: `22`) |
| `user` | string | ✅ | 远程用户名 |
| `password` | string | ❌ | SSH 密码 (使用私钥时可选) |
| `privateKey` | string | ❌ | SSH 私钥内容 (PEM 格式) |
| `command` | string | ✅ | 要执行的命令 |
| `workingDir` | string | ❌ | 命令执行的工作目录 |
| `usePty` | boolean | ❌ | 是否启用 PTY (用于交互式命令) |

---

### `scp_upload` 工具

通过 SFTP 协议上传文件到远程服务器。

#### 参数说明

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| `host` | string | ✅ | 远程主机地址 |
| `port` | string | ✅ | SSH 端口 (默认: `22`) |
| `user` | string | ✅ | 远程用户名 |
| `password` | string | ❌ | SSH 密码 |
| `privateKey` | string | ❌ | SSH 私钥 (PEM 格式) |
| `localPath` | string | ❌ | 本地文件路径 (`localPath` 和 `content` 二选一) |
| `content` | string | ❌ | Base64 编码的文件内容 |
| `remotePath` | string | ✅ | 远程目标路径 |
| `overwrite` | boolean | ❌ | 是否覆盖已存在的文件 (默认: `false`) |

---

### `scp_download` 工具

通过 SFTP 协议从远程服务器下载文件。

#### 参数说明

| 参数 | 类型 | 必填 | 描述 |
|------|------|------|------|
| `host` | string | ✅ | 远程主机地址 |
| `port` | string | ✅ | SSH 端口 (默认: `22`) |
| `user` | string | ✅ | 远程用户名 |
| `password` | string | ❌ | SSH 密码 |
| `privateKey` | string | ❌ | SSH 私钥 (PEM 格式) |
| `remotePath` | string | ✅ | 远程文件路径 |
| `localPath` | string | ❌ | 本地保存路径 (不提供则返回 Base64 内容) |
| `maxSize` | number | ❌ | 最大下载大小 (字节，默认: 10MB) |

> ⚠️ **注意：** 所有工具均需提供 `password` 或 `privateKey` 其一。

---

## 🛡️ 安全特性

### 命令黑名单

以下危险命令默认被拦截：

| 拦截模式 | 风险等级 | 描述 |
|----------|----------|------|
| `rm -rf /` | 🔴 极高 | 递归删除根目录 |
| `rm -rf *` | 🔴 极高 | 递归删除当前目录 |
| `mkfs` | 🔴 极高 | 格式化文件系统 |
| `shutdown` | 🟠 高 | 关机 |
| `reboot` | 🟠 高 | 重启 |
| `init 0` / `init 6` | 🟠 高 | 运行级别切换 |
| `dd if=` | 🟠 高 | 原始磁盘操作 |
| `:(){ :|:& };:` | 🔴 极高 | Fork 炸弹 |

### 安全最佳实践

1. **优先使用私钥** - 比密码更安全
2. **最小权限原则** - 创建专用 SSH 用户，授予最小权限
3. **网络隔离** - 在受信任的网络环境中运行 MCP 服务
4. **主机密钥验证** - 生产环境应配置适当的主机密钥检查

---

## 🏗️ 架构设计

### 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | Go 1.22+ |
| MCP SDK | [mcp-go](https://github.com/mark3labs/mcp-go) |
| SSH 库 | [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) |
| 协议 | Model Context Protocol (MCP) |
| 传输 | stdio |

### 连接池设计

```
┌─────────────────────────────────────────────────┐
│                 SSH MCP Server                  │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────┐    ┌─────────────────────┐    │
│  │ MCP 处理器  │───▶│      连接池         │    │
│  └─────────────┘    ├─────────────────────┤    │
│                     │ user@host:port → conn│    │
│                     │ user@host:port → conn│    │
│                     └─────────────────────┘    │
│                              │                  │
│                     ┌────────▼────────┐        │
│                     │   空闲清理器     │        │
│                     │  (每 1 分钟)     │        │
│                     │  TTL: 5 分钟     │        │
│                     └─────────────────┘        │
│                                                 │
└─────────────────────────────────────────────────┘
```

### 设计原则

- 🔒 **安全优先** - 命令黑名单、结构化错误处理
- ⚡ **高性能** - 连接池、Keepalive 检测
- 🛡️ **高可靠** - 自动重试、优雅错误恢复
- 🎯 **简洁** - 单一工具、清晰 API

---

## 🔧 故障排查

### "Either password or privateKey must be provided"

**原因：** 未提供任何认证方式。

**解决：** 在请求中提供 `password` 或 `privateKey`。

### "Failed to parse private key"

**原因：** 私钥格式无效。

**解决：**
- 确保私钥为 PEM 格式
- 包含完整的密钥内容和头尾标识 (`-----BEGIN ... -----`)
- 检查是否有多余空格或编码问题

### "SECURITY_ERROR: The command contains restricted pattern"

**原因：** 命令匹配了黑名单中的危险模式。

**解决：**
- 检查并修改命令，避免触发危险模式
- 如确有合法需求，可在 `main.go` 中调整黑名单

### 连接超时

**原因：** 网络问题或防火墙阻止。

**解决：**
- 确认主机地址和端口正确
- 检查防火墙规则
- 确保远程主机的 SSH 服务正在运行

---

## 🗺️ 路线图

### ✅ 已完成
- [x] 连接池 + Keepalive 保活
- [x] PTY 交互式命令支持
- [x] 连接失败自动重试
- [x] 大输出智能截断
- [x] 命令黑名单安全过滤
- [x] 双重认证 (密码/私钥)
- [x] 工作目录指定
- [x] **SCP/SFTP 文件上传/下载**

### 🚀 计划中
- [ ] 端口转发 (隧道)
- [ ] 多跳 SSH (跳板机)
- [ ] 自定义超时配置
- [ ] 主机密钥验证
- [ ] 会话多路复用
- [ ] 从文件执行脚本

---

## 🤝 贡献指南

欢迎贡献！请随时提交 Pull Request。

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

---

## 📄 开源协议

[MIT](LICENSE) © SSH MCP Server 贡献者

---

## 🙏 致谢

本项目基于以下优秀开源项目构建：

- [mcp-go](https://github.com/mark3labs/mcp-go) - Go MCP SDK
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - Go 加密库
- [Model Context Protocol](https://modelcontextprotocol.io/) - 协议规范

---

<p align="center">
  <b>连接池管理</b> • <b>PTY 支持</b> • <b>自动重连</b> • <b>安全卫士</b>
</p>
