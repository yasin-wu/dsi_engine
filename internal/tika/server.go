package tika

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"time"
)

type Server struct {
	jar       string
	url       string // url is derived from port.
	port      string
	cmd       *exec.Cmd
	child     *ChildOptions
	JavaProps map[string]string
}

type ChildOptions struct {
	MaxFiles          int
	TaskPulseMillis   int
	TaskTimeoutMillis int
	PingPulseMillis   int
	PingTimeoutMillis int
}

func (co *ChildOptions) args() []string {
	if co == nil {
		return nil
	}
	var args []string
	args = append(args, "-spawnChild")
	if co.MaxFiles == -1 || co.MaxFiles > 0 {
		args = append(args, "-maxFiles", strconv.Itoa(co.MaxFiles))
	}
	if co.TaskPulseMillis > 0 {
		args = append(args, "-taskPulseMillis", strconv.Itoa(co.TaskPulseMillis))
	}
	if co.TaskTimeoutMillis > 0 {
		args = append(args, "-taskTimeoutMillis", strconv.Itoa(co.TaskTimeoutMillis))
	}
	if co.PingPulseMillis > 0 {
		args = append(args, "-pingPulseMillis", strconv.Itoa(co.PingPulseMillis))
	}
	if co.PingTimeoutMillis > 0 {
		args = append(args, "-pingTimeoutMillis", strconv.Itoa(co.PingTimeoutMillis))
	}
	return args
}

func (s *Server) URL() string {
	return s.url
}

func NewServer(jar, port string) (*Server, error) {
	if jar == "" {
		return nil, fmt.Errorf("no jar file specified")
	}
	if port == "" {
		port = "9998"
	}

	urlString := "http://localhost:" + port
	u, err := url.Parse(urlString)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", port, err)
	}

	s := &Server{
		jar:       jar,
		port:      port,
		url:       u.String(),
		JavaProps: map[string]string{},
	}

	return s, nil
}

func (s *Server) ChildMode(ops *ChildOptions) error {
	if s.cmd != nil {
		return fmt.Errorf("server process already started, cannot switch to spawn child mode")
	}
	s.child = ops
	return nil
}

var command = exec.Command

func (s *Server) Start(ctx context.Context) error {
	if _, err := os.Stat(s.jar); os.IsNotExist(err) {
		return err
	}

	var props []string //nolint:prealloc
	for k, v := range s.JavaProps {
		props = append(props, fmt.Sprintf("-D%s=%q", k, v))
	}

	args := append(append(props, "-jar", s.jar, "-p", s.port), s.child.args()...)
	cmd := command("java", args...)

	if err := cmd.Start(); err != nil {
		return err
	}
	s.cmd = cmd

	if err := s.waitForStart(ctx); err != nil {
		out, readErr := cmd.CombinedOutput()
		if readErr != nil {
			return fmt.Errorf("error reading output: %w", readErr)
		}
		// Report stderr since sometimes the server says why it failed to start.
		return fmt.Errorf("error starting server: %w\nserver stderr:\n\n%s", err, out)
	}
	return nil
}

func (s Server) waitForStart(ctx context.Context) error {
	c := NewClient(nil, s.url)
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if _, err := c.Version(ctx); err == nil {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Server) Stop() error {
	if err := s.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("could not kill server: %w", err)
	}
	if err := s.cmd.Wait(); err != nil {
		return fmt.Errorf("could not wait for server to finish: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
		return fmt.Errorf("could not interrupt server: %w", err)
	}
	errChannel := make(chan error)
	go func() {
		select {
		case errChannel <- s.cmd.Wait():
		case <-ctx.Done():
		}
	}()
	select {
	case err := <-errChannel:
		if err != nil {
			return fmt.Errorf("could not wait for server to finish: %w", err)
		}
	case <-ctx.Done():
		if err := s.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("could not kill server: %w", err)
		}
	}
	return nil
}

// A Version represents a Tika Server version.
type Version string
