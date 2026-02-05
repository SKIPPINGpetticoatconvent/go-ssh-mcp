package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/pkg/sftp"
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

func (p *sshPool) removeConnection(user, host, port string) {
	key := fmt.Sprintf("%s@%s:%s", user, host, port)
	p.mu.Lock()
	defer p.mu.Unlock()
	if conn, ok := p.conns[key]; ok {
		conn.client.Close()
		delete(p.conns, key)
	}
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
		mcp.WithDescription("在远程计算机上执行 SSH 命令 (支持连接池、PTY 及自动重连)"),
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

	// 定义 scp_upload 工具
	scpUploadTool := mcp.NewTool("scp_upload",
		mcp.WithDescription("上传文件到远程服务器 (通过 SFTP 协议)"),
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
		mcp.WithString("localPath",
			mcp.Description("本地文件路径 (与 content 二选一)"),
		),
		mcp.WithString("content",
			mcp.Description("文件内容 (Base64 编码，与 localPath 二选一)"),
		),
		mcp.WithString("remotePath",
			mcp.Required(),
			mcp.Description("远程目标路径 (例如: /home/user/file.txt)"),
		),
		mcp.WithBoolean("overwrite",
			mcp.Description("是否覆盖已存在的文件 (默认: false)"),
		),
	)

	// 定义 scp_download 工具
	scpDownloadTool := mcp.NewTool("scp_download",
		mcp.WithDescription("从远程服务器下载文件 (通过 SFTP 协议)"),
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
		mcp.WithString("remotePath",
			mcp.Required(),
			mcp.Description("远程文件路径 (例如: /home/user/file.txt)"),
		),
		mcp.WithString("localPath",
			mcp.Description("本地保存路径 (可选，不提供则返回 Base64 内容)"),
		),
		mcp.WithNumber("maxSize",
			mcp.Description("最大下载大小 (字节，默认: 10MB)"),
		),
	)

	// 添加工具处理程序
	s.AddTool(sshTool, sshExecuteHandler)
	s.AddTool(scpUploadTool, scpUploadHandler)
	s.AddTool(scpDownloadTool, scpDownloadHandler)

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
		finalCommand = fmt.Sprintf("cd %s && %s", workingDir, command)
	}

	// 命令黑名单检查 (针对拼接后的最终命令)
	lowerCommand := strings.ToLower(finalCommand)
	for _, restricted := range blacklistedCommands {
		if strings.Contains(lowerCommand, strings.ToLower(restricted)) {
			return mcp.NewToolResultError(fmt.Sprintf("[SECURITY_ERROR] The command contains restricted pattern '%s'. This operation is blocked for safety.", restricted)), nil
		}
	}

	config, err := createSSHConfig(user, password, privateKey)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	stdout, stderr, err := runWithRetry(user, host, port, config, finalCommand, usePty)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("SSH Error: %v\nStderr: %s", err, stderr)), nil
	}

	// 增强型文件感知: 自动截断过大的输出 (针对日志等场景优化)
	const maxOutputSize = 2000
	if len(stdout) > maxOutputSize {
		stdout = fmt.Sprintf("[Output Truncated: Only showing the last %d bytes for performance reasons]\n%s",
			maxOutputSize, stdout[len(stdout)-maxOutputSize:])
	}

	resultText := stdout
	if stderr != "" {
		resultText = fmt.Sprintf("Standard Output:\n%s\n\nStandard Error:\n%s", stdout, stderr)
	}

	return mcp.NewToolResultText(resultText), nil
}

func runWithRetry(user, host, port string, config *ssh.ClientConfig, command string, usePty bool) (string, string, error) {
	stdout, stderr, err := executeCommand(user, host, port, config, command, usePty)
	if err != nil {
		// 检查是否为连接错误（EOF 或 broken pipe 或 handshake failed 可能是因为连接坏了）
		if err == io.EOF || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "handshake failed") {
			// 强制从池中移除连接并重试一次
			pool.removeConnection(user, host, port)
			return executeCommand(user, host, port, config, command, usePty)
		}
	}
	return stdout, stderr, err
}

func executeCommand(user, host, port string, config *ssh.ClientConfig, command string, usePty bool) (string, string, error) {
	client, err := pool.getConnection(user, host, port, config)
	if err != nil {
		return "", "", err
	}

	session, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	if usePty {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
			return "", "", fmt.Errorf("failed to request pty: %w", err)
		}
	}

	err = session.Run(command)
	return stdoutBuf.String(), stderrBuf.String(), err
}

// createSSHConfig 创建 SSH 客户端配置
func createSSHConfig(user, password, privateKey string) (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	// 如果没有提供私钥和密码，尝试自动读取默认私钥
	if len(authMethods) == 0 {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			defaultKeyPaths := []string{
				filepath.Join(homeDir, ".ssh", "id_rsa"),
				filepath.Join(homeDir, ".ssh", "id_ed25519"),
				filepath.Join(homeDir, ".ssh", "id_ecdsa"),
			}

			for _, path := range defaultKeyPaths {
				keyData, err := os.ReadFile(path)
				if err == nil {
					signer, err := ssh.ParsePrivateKey(keyData)
					if err == nil {
						authMethods = append(authMethods, ssh.PublicKeys(signer))
						// 找到一个可用的就够了？也可以支持多个，这里先只加一个找到的
						// ssh.PublicKeys 可以接受多个 signer，但为了简单起见，我们通常只需要一个有效的
						// 不过如果用户有多个 key，且服务器只接受其中一个，最好还是都试一下或者怎么处理？
						// 既然 authMethods 是列表，我们可以尝试添加所有找到的 key
					}
				}
			}
		}
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods configured (password, privateKey, or default SSH keys)")
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}, nil
}

// scpUploadHandler 处理文件上传
func scpUploadHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host := request.GetString("host", "")
	port := request.GetString("port", "22")
	user := request.GetString("user", "")
	password := request.GetString("password", "")
	privateKey := request.GetString("privateKey", "")
	localPath := request.GetString("localPath", "")
	content := request.GetString("content", "")
	remotePath := request.GetString("remotePath", "")
	overwrite := request.GetBool("overwrite", false)

	if host == "" || user == "" || remotePath == "" {
		return mcp.NewToolResultError("host, user, and remotePath are required parameters"), nil
	}

	if localPath == "" && content == "" {
		return mcp.NewToolResultError("Either localPath or content must be provided"), nil
	}

	// 创建 SSH 配置
	config, err := createSSHConfig(user, password, privateKey)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// 获取 SSH 连接
	client, err := pool.getConnection(user, host, port, config)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("SSH connection failed: %v", err)), nil
	}

	// 创建 SFTP 客户端
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("SFTP client creation failed: %v", err)), nil
	}
	defer sftpClient.Close()

	// 检查远程文件是否存在
	if !overwrite {
		if _, err := sftpClient.Stat(remotePath); err == nil {
			return mcp.NewToolResultError(fmt.Sprintf("Remote file already exists: %s. Set overwrite=true to replace.", remotePath)), nil
		}
	}

	// 获取要上传的数据
	var data []byte
	var sourceInfo string
	if localPath != "" {
		// 从本地文件读取
		data, err = os.ReadFile(localPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to read local file: %v", err)), nil
		}
		sourceInfo = fmt.Sprintf("local file: %s", localPath)
	} else {
		// 从 Base64 内容解码
		data, err = base64.StdEncoding.DecodeString(content)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to decode Base64 content: %v", err)), nil
		}
		sourceInfo = "Base64 content"
	}

	// 确保远程目录存在
	remoteDir := filepath.Dir(remotePath)
	if remoteDir != "." && remoteDir != "/" {
		if err := sftpClient.MkdirAll(remoteDir); err != nil {
			// 忽略目录已存在的错误
			if !strings.Contains(err.Error(), "exists") {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to create remote directory: %v", err)), nil
			}
		}
	}

	// 创建远程文件
	remoteFile, err := sftpClient.Create(remotePath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create remote file: %v", err)), nil
	}
	defer remoteFile.Close()

	// 写入数据
	bytesWritten, err := remoteFile.Write(data)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to write to remote file: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Successfully uploaded %d bytes from %s to %s:%s",
		bytesWritten, sourceInfo, host, remotePath)), nil
}

// scpDownloadHandler 处理文件下载
func scpDownloadHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	host := request.GetString("host", "")
	port := request.GetString("port", "22")
	user := request.GetString("user", "")
	password := request.GetString("password", "")
	privateKey := request.GetString("privateKey", "")
	remotePath := request.GetString("remotePath", "")
	localPath := request.GetString("localPath", "")
	maxSize := int64(request.GetFloat("maxSize", 10*1024*1024)) // 默认 10MB

	if host == "" || user == "" || remotePath == "" {
		return mcp.NewToolResultError("host, user, and remotePath are required parameters"), nil
	}

	// 创建 SSH 配置
	config, err := createSSHConfig(user, password, privateKey)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// 获取 SSH 连接
	client, err := pool.getConnection(user, host, port, config)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("SSH connection failed: %v", err)), nil
	}

	// 创建 SFTP 客户端
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("SFTP client creation failed: %v", err)), nil
	}
	defer sftpClient.Close()

	// 获取远程文件信息
	fileInfo, err := sftpClient.Stat(remotePath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Remote file not found: %v", err)), nil
	}

	if fileInfo.IsDir() {
		return mcp.NewToolResultError("Cannot download a directory. Please specify a file path."), nil
	}

	// 检查文件大小
	if fileInfo.Size() > maxSize {
		return mcp.NewToolResultError(fmt.Sprintf("File too large: %d bytes (max: %d bytes). Increase maxSize parameter if needed.",
			fileInfo.Size(), maxSize)), nil
	}

	// 打开远程文件
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to open remote file: %v", err)), nil
	}
	defer remoteFile.Close()

	// 读取文件内容
	data, err := io.ReadAll(remoteFile)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to read remote file: %v", err)), nil
	}

	// 如果指定了本地路径，保存到文件
	if localPath != "" {
		// 确保本地目录存在
		localDir := filepath.Dir(localPath)
		if err := os.MkdirAll(localDir, 0o755); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create local directory: %v", err)), nil
		}

		if err := os.WriteFile(localPath, data, 0o644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to write local file: %v", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Successfully downloaded %d bytes from %s:%s to %s",
			len(data), host, remotePath, localPath)), nil
	}

	// 否则返回 Base64 编码的内容
	encoded := base64.StdEncoding.EncodeToString(data)
	return mcp.NewToolResultText(fmt.Sprintf("Downloaded %d bytes from %s:%s\n\nBase64 Content:\n%s",
		len(data), host, remotePath, encoded)), nil
}
