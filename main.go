package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"golang.org/x/crypto/ssh"
)

var blacklistedCommands = []string{
	"rm -rf /",
	"mkfs",
	"shutdown",
	"reboot",
	"init 0",
	"init 6",
	"dd if=",
	":(){ :|:& };:",
	"rm -rf *",
}

type sshConn struct {
	client   *ssh.Client
	lastUsed time.Time
}

type sshPool struct {
	mu    sync.Mutex
	conns map[string]*sshConn
}

var pool = &sshPool{
	conns: make(map[string]*sshConn),
}

func (p *sshPool) getConnection(user, host, port string, config *ssh.ClientConfig) (*ssh.Client, error) {
	key := fmt.Sprintf("%s@%s:%s", user, host, port)
	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, ok := p.conns[key]; ok {
		// 检查连接是否仍然存活
		_, _, err := conn.client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			conn.lastUsed = time.Now()
			return conn.client, nil
		}
		// 连接已断开，关闭并移除
		conn.client.Close()
		delete(p.conns, key)
	}

	// 建立新连接
	addr := net.JoinHostPort(host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	p.conns[key] = &sshConn{
		client:   client,
		lastUsed: time.Now(),
	}
	return client, nil
}

func (p *sshPool) cleanupIdle() {
	for {
		time.Sleep(1 * time.Minute)
		p.mu.Lock()
		now := time.Now()
		for key, conn := range p.conns {
			if now.Sub(conn.lastUsed) > 5*time.Minute {
				conn.client.Close()
				delete(p.conns, key)
			}
		}
		p.mu.Unlock()
	}
}

func main() {
	// 启动清理协程
	go pool.cleanupIdle()

	// 创建新的 MCP 服务器
	s := server.NewMCPServer(
		"SSH Command Server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	// 定义 ssh_execute 工具
	sshTool := mcp.NewTool("ssh_execute",
		mcp.WithDescription("在远程计算机上执行 SSH 命令 (支持连接池)"),
		mcp.WithString("host",
			mcp.Required(),
			mcp.Description("远程主机地址 (例如: 127.0.0.1)"),
		),
		mcp.WithString("port",
			mcp.Required(),
			mcp.Description("SSH 端口 (例如: 22)"),
		),
		mcp.WithString("user",
			mcp.Required(),
			mcp.Description("远程用户账号"),
		),
		mcp.WithString("password",
			mcp.Description("SSH 登录密码 (如果使用密钥，则可省略)"),
		),
		mcp.WithString("privateKey",
			mcp.Description("SSH 私钥内容 (PEM 格式)"),
		),
		mcp.WithString("workingDir",
			mcp.Description("执行命令的工作目录 (例如: /etc)"),
		),
		mcp.WithBoolean("usePty",
			mcp.Description("是否启用 PTY 伪终端 (用于执行 top, htop 等交互式命令)"),
		),
		mcp.WithString("command",
			mcp.Required(),
			mcp.Description("要执行的命令"),
		),
	)

	// 添加工具处理程序
	s.AddTool(sshTool, sshExecuteHandler)

	// 启动 stdio 服务器
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}

func sshExecuteHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host := request.GetString("host", "")
	port := request.GetString("port", "22")
	user := request.GetString("user", "")
	password := request.GetString("password", "")
	privateKey := request.GetString("privateKey", "")
	workingDir := request.GetString("workingDir", "")
	usePty := request.GetBool("usePty", false)
	command := request.GetString("command", "")

	if host == "" || user == "" || command == "" {
		return mcp.NewToolResultError("host, user, and command are required parameters"), nil
	}

	// 拼接工作目录切换逻辑
	finalCommand := command
	if workingDir != "" {
		// 使用 cd 切换目录后再执行命令
		finalCommand = fmt.Sprintf("cd %s && %s", workingDir, command)
	}

	// 命令黑名单检查 (针对拼接后的最终命令)
	lowerCommand := strings.ToLower(finalCommand)
	for _, restricted := range blacklistedCommands {
		if strings.Contains(lowerCommand, strings.ToLower(restricted)) {
			return mcp.NewToolResultError(fmt.Sprintf("Security Alert: The command contains restricted pattern '%s'. This operation is blocked for safety.", restricted)), nil
		}
	}

	var authMethods []ssh.AuthMethod

	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to parse private key: %v", err)), nil
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	} else {
		return mcp.NewToolResultError("Either password or privateKey must be provided"), nil
	}

	// SSH 客户端配置
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 警告: 仅用于演示，生产环境应验证主机密钥
		Timeout:         10 * time.Second,
	}

	// 从池中获取连接
	client, err := pool.getConnection(user, host, port, config)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to connect: %v", err)), nil
	}

	// 创建会话
	session, err := client.NewSession()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create session: %v", err)), nil
	}
	defer session.Close()

	if usePty {
		// 请求伪终端
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // 禁用回显
			ssh.TTY_OP_ISPEED: 14400, // 输入速度
			ssh.TTY_OP_OSPEED: 14400, // 输出速度
		}
		if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to request pty: %v", err)), nil
		}
	}

	// 执行最终拼接的命令并获取输出
	output, err := session.CombinedOutput(finalCommand)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Command execution failed: %v\nOutput: %s", err, string(output))), nil
	}

	return mcp.NewToolResultText(string(output)), nil
}
