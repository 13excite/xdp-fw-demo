package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/13excite/xdp-fw-demo/pkg/internal/config"
)

type Client struct {
	g *config.TGlobal
}

func NewClient(g *config.TGlobal) *Client {
	return &Client{g: g}
}

const (
	// number of milliseconds for timeout in a
	// client http call
	DefaultHTTPTimeout = 2000
)

// Request performs an http call against the running daemon's
// api and returns the raw body, the status code and an error.
func (m *Client) Request(method string, uri string, content []byte) ([]byte, int, error) {
	id := "(client) (http)"

	t0 := time.Now()

	url := fmt.Sprintf("http://%s%s/%s", m.g.Opts.GetListenAddr(),
		CurrentAPIVersion, uri)

	m.g.L.Debugf("%s requesting '%s' data over endpoint:'%s'", id, uri, url)
	m.g.L.DumpBytes(id, content, 0)

	reader := bytes.NewReader(content)

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(DefaultHTTPTimeout)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", m.g.Runtime.GetUseragent())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return nil, resp.StatusCode, err
	}

	m.g.L.Debugf("%s received size:'%d' code:'%d' in '%s'",
		id, len(body), resp.StatusCode, time.Since(t0))

	return body, resp.StatusCode, nil
}
