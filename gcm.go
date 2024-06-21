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

type GCMRegistrationOpts struct {
	AppID      string
	InstanceID string
}

func RegisterGCM(ctx context.Context, authorizationEntity string, creds GCMCredentials, opts *GCMRegistrationOpts) (*FCMCredentials, error) {
	values := url.Values{}

	var appID string
	if opts != nil {
		appID = opts.AppID
		values.Set("appId", opts.InstanceID)
	} else {
		appID = uuid.New().String()
	}

	values.Set("app", "org.chromium.linux")
	values.Set("scope", "GCM")
	values.Set("X-scope", "GCM")
	values.Set("X-subtype", appID)
	values.Set("device", fmt.Sprint(creds.AndroidID))
	values.Set("gmsv", strings.Split(chromeVersion, ".")[0])
	values.Set("sender", authorizationEntity)

	res, err := postRequest(ctx, registerURL, strings.NewReader(values.Encode()), func(header *http.Header) {
		header.Set("Content-Type", "application/x-www-form-urlencoded")
		header.Set("Authorization", fmt.Sprintf("AidLogin %d:%d", creds.AndroidID, creds.SecurityToken))
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

	return &FCMCredentials{
		GCM:   creds,
		Token: token,
		AppID: appID,
	}, nil
}
