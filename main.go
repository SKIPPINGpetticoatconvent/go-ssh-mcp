package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
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

func main() {
	// 创建新的 MCP 服务器
	s := server.NewMCPServer(
		"SSH Command Server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	// 定义 ssh_execute 工具
	sshTool := mcp.NewTool("ssh_execute",
		mcp.WithDescription("在远程计算机上执行 SSH 命令"),
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
	command := request.GetString("command", "")

	if host == "" || user == "" || command == "" {
		return mcp.NewToolResultError("host, user, and command are required parameters"), nil
	}

	// 命令黑名单检查
	lowerCommand := strings.ToLower(command)
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

	// 建立连接
	addr := net.JoinHostPort(host, port)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to dial: %v", err)), nil
	}
	defer client.Close()

	// 创建会话
	session, err := client.NewSession()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create session: %v", err)), nil
	}
	defer session.Close()

	// 执行命令并获取输出
	output, err := session.CombinedOutput(command)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Command execution failed: %v\nOutput: %s", err, string(output))), nil
	}

	return mcp.NewToolResultText(string(output)), nil
}
