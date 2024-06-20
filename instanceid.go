/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of go-push-receiver, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package pushreceiver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type gcmRegisterResponse struct {
	token         string
	androidID     uint64
	securityToken uint64
	appID         string
}

func (c *Client) registerGCM(ctx context.Context) (*gcmRegisterResponse, error) {
	checkInResp, err := CheckIn(ctx, nil)
	if err != nil {
		return nil, err
	}
	return c.doRegister(ctx, *checkInResp.AndroidId, *checkInResp.SecurityToken)
}

func (c *Client) doRegister(ctx context.Context, androidID uint64, securityToken uint64) (*gcmRegisterResponse, error) {
	appID := fmt.Sprintf("wp:receiver.push.com#%s", uuid.New())

	values := url.Values{}
	values.Set("app", "org.chromium.linux")
	values.Set("X-subtype", appID)
	values.Set("device", fmt.Sprint(androidID))
	values.Set("sender", fcmServerKey)

	res, err := c.post(ctx, registerURL, strings.NewReader(values.Encode()), func(header *http.Header) {
		header.Set("Content-Type", "application/x-www-form-urlencoded")
		header.Set("Authorization", fmt.Sprintf("AidLogin %d:%d", androidID, securityToken))
	})
	if err != nil {
		return nil, errors.Wrap(err, "request GCM register")
	}
	defer closeResponse(res)

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read GCM register response")
	}

	subscription, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, errors.Wrap(err, "parse GCM register URL")
	}
	token := subscription.Get("token")

	return &gcmRegisterResponse{
		token:         token,
		androidID:     androidID,
		securityToken: securityToken,
		appID:         appID,
	}, nil
}
