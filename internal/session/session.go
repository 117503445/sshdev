package session

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/117503445/sshdev/internal/types"
	"github.com/pkg/sftp"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// terminalRequest 保存客户端终端类型、尺寸和模式。
type terminalRequest struct {
	Term                         string
	Columns, Rows, Width, Height uint32
	Modes                        string
}

// process 保存运行中进程的控制操作，由请求循环和等待协程共同持有。
type process struct {
	signal func(string) error
	resize func(uint32, uint32) error
	kill   func()
	wait   func() (uint32, string)
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	closed bool
}

// stop 仅执行一次进程树清理。
func (p *process) stop() {
	p.once.Do(func() { p.mu.Lock(); defer p.mu.Unlock(); p.closed = true; p.kill() })
}

// finish 等待进程，发送退出结果并关闭 ch；ctx 用于记录执行结果。
func (p *process) finish(ctx context.Context, ch ssh.Channel) {
	defer close(p.done)
	code, signal := p.wait()
	p.stop()
	if signal != "" {
		_, _ = ch.SendRequest("exit-signal", false, ssh.Marshal(struct {
			Signal            string
			CoreDumped        bool
			Message, Language string
		}{signal, false, "", ""}))
	}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{code}))
	log.Ctx(ctx).Debug().Uint32("exitCode", code).Str("signal", signal).Msg("会话进程退出")
	ch.Close()
}

// HandleSession 处理 newChannel 的会话请求；ctx 提供日志，cfg 指定 shell。
func HandleSession(ctx context.Context, newChannel ssh.NewChannel, cfg *types.Config) {
	ch, requests, err := newChannel.Accept()
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("接受会话失败")
		return
	}
	defer ch.Close()
	env := os.Environ()
	var term *terminalRequest
	var active *process
	started := false
	defer func() {
		if active != nil {
			active.stop()
			<-active.done
		}
	}()
	for req := range requests {
		accepted := false
		switch req.Type {
		case "env":
			var msg struct{ Name, Value string }
			if !started && ssh.Unmarshal(req.Payload, &msg) == nil {
				env = append(env, msg.Name+"="+msg.Value)
				accepted = true
			}
		case "pty-req":
			msg := new(terminalRequest)
			if !started && term == nil && ssh.Unmarshal(req.Payload, msg) == nil && validSize(msg.Columns, msg.Rows) {
				term = msg
				accepted = true
			}
		case "shell", "exec":
			if !started {
				command := ""
				valid := len(req.Payload) == 0
				if req.Type == "exec" {
					var msg struct{ Command string }
					valid = ssh.Unmarshal(req.Payload, &msg) == nil
					command = msg.Command
				}
				if valid {
					active, err = startProcess(ch, cfg.Shell, command, req.Type == "exec", env, term)
					if err == nil {
						started = true
						accepted = true
					} else {
						log.Ctx(ctx).Warn().Err(err).Msg("启动会话进程失败")
					}
				}
			}
		case "window-change":
			var msg struct{ Columns, Rows, Width, Height uint32 }
			if term != nil && ssh.Unmarshal(req.Payload, &msg) == nil && validSize(msg.Columns, msg.Rows) {
				if active == nil {
					term.Columns = msg.Columns
					term.Rows = msg.Rows
					accepted = true
				} else {
					active.mu.Lock()
					if !active.closed {
						accepted = active.resize(msg.Columns, msg.Rows) == nil
					}
					active.mu.Unlock()
				}
			}
		case "signal":
			var msg struct{ Signal string }
			if active != nil && ssh.Unmarshal(req.Payload, &msg) == nil {
				active.mu.Lock()
				if !active.closed {
					accepted = active.signal(msg.Signal) == nil
				}
				active.mu.Unlock()
			}
		case "subsystem":
			var msg struct{ Name string }
			if !started && ssh.Unmarshal(req.Payload, &msg) == nil && msg.Name == "sftp" {
				server, e := sftp.NewServer(ch, sftp.WindowsRootEnumeratesDrives())
				if e != nil {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					return
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				// SFTP 接管整个 channel，Serve 返回时会释放所有打开的文件。
				if e = server.Serve(); e != nil && e != io.EOF {
					log.Ctx(ctx).Debug().Err(e).Msg("SFTP 会话结束")
				}
				server.Close()
				return
			}
		}
		if req.WantReply {
			_ = req.Reply(accepted, nil)
		}
		if accepted && (req.Type == "exec" || req.Type == "shell") {
			go active.finish(ctx, ch)
		}
	}
}

// validSize 校验终端列数 columns 与行数 rows，避免平台整数截断。
func validSize(columns, rows uint32) bool {
	return columns > 0 && rows > 0 && columns <= 32767 && rows <= 32767
}

// unsupportedSignal 返回 name 所指定信号不受当前执行模式支持的错误。
func unsupportedSignal(name string) error { return fmt.Errorf("不支持信号 %q", name) }
