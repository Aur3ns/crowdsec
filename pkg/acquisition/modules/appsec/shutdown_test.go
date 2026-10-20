package appsecacquisition

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
)

func newShutdownTestSource() (*Source, chan struct{}) {
	logger := log.New()
	logger.SetOutput(io.Discard)

	stopping := make(chan struct{})
	bodyTimeout := time.Second
	source := &Source{
		logger:        log.NewEntry(logger),
		config:        Configuration{Name: "test-appsec", BodyReadTimeout: &bodyTimeout},
		AuthCache:     NewAuthCache(),
		InChan:        make(chan appsec.ParsedRequest),
		AppsecRuntime: &appsec.AppsecRuntimeConfig{},
		stopping:      stopping,
	}
	source.AuthCache.Set("test-key", time.Now().Add(time.Minute))

	return source, stopping
}

func shutdownTestRequest(ctx context.Context) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).WithContext(ctx)
	req.Header.Set(appsec.APIKeyHeaderName, "test-key")
	req.Header.Set(appsec.IPHeaderName, "192.0.2.1")
	req.Header.Set(appsec.URIHeaderName, "/")
	req.Header.Set(appsec.VerbHeaderName, http.MethodGet)
	return req
}

func TestAppsecHandlerStopsWaitingOnShutdown(t *testing.T) {
	tests := []struct {
		name          string
		acceptRequest bool
		cancelRequest bool
	}{
		{name: "runner stopped before accepting"},
		{name: "runner accepted but never replied", acceptRequest: true},
		{name: "client cancelled while awaiting response", acceptRequest: true, cancelRequest: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source, stopping := newShutdownTestSource()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			result := make(chan int, 1)
			go func() {
				recorder := httptest.NewRecorder()
				source.appsecHandler(recorder, shutdownTestRequest(ctx))
				result <- recorder.Code
			}()

			var accepted appsec.ParsedRequest
			if tc.acceptRequest {
				select {
				case accepted = <-source.InChan:
				case <-time.After(3 * time.Second):
					t.Fatal("handler never delivered request to runner")
				}
			}

			if tc.cancelRequest {
				cancel()
			} else {
				close(stopping)
			}

			select {
			case status := <-result:
				require.Equal(t, http.StatusServiceUnavailable, status)
			case <-time.After(3 * time.Second):
				t.Fatal("AppSec handler remained blocked after shutdown")
			}

			if tc.acceptRequest {
				// The runner can finish after the HTTP handler exits; its send must not block.
				select {
				case accepted.ResponseChannel <- appsec.AppsecTempResponse{}:
				default:
					t.Fatal("runner would block sending a late response")
				}
			}
		})
	}
}

func TestAppsecShutdownClosesStuckConnections(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{Handler: handler}
	defer server.Close()

	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	client := &http.Client{Timeout: 3 * time.Second}
	requestDone := make(chan error, 1)
	go func() {
		res, err := client.Get("http://" + listener.Addr().String())
		if res != nil {
			_ = res.Body.Close()
		}
		requestDone <- err
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("test HTTP request never reached the server")
	}

	logger := log.New()
	logger.SetOutput(io.Discard)
	source := &Source{logger: log.NewEntry(logger), server: server}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	tb := &tomb.Tomb{}
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- source.listenAndServe(ctx, tb) }()
	tb.Kill(nil)

	select {
	case err := <-shutdownDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("AppSec listener did not stop after shutdown deadline")
	}

	select {
	case err := <-requestDone:
		require.Error(t, err, "stuck connection should have been forcibly closed")
	case <-time.After(2 * time.Second):
		t.Fatal("stuck HTTP connection survived shutdown deadline")
	}

	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP Serve goroutine did not exit")
	}
}
