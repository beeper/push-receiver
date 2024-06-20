package pushreceiver

import (
	"context"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

func postRequest(ctx context.Context, url string, body io.Reader, headerSetter func(*http.Header)) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, errors.Wrap(err, "create post request error")
	}
	headerSetter(&req.Header)

	client := &http.Client{}
	return client.Do(req)
}
