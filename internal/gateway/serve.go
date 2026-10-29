package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

func Serve(ctx context.Context, server *http.Server, ln net.Listener, drain time.Duration) error {
	failed := make(chan error, 1)
	go func() { failed <- server.Serve(ln) }()
	select {
	case err := <-failed:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	return server.Shutdown(shutdown)
}
