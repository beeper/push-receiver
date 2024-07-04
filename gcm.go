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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type GCMRegistrationOpts struct {
	AppID      string
	InstanceID string
	Expiry     time.Duration
}

func RegisterGCM(ctx context.Context, authorizationEntity string, creds GCMCredentials, opts *GCMRegistrationOpts) (*FCMCredentials, error) {
	values := url.Values{}

	var appID string
	if opts != nil && opts.AppID != "" {
		appID = opts.AppID
	} else {
		appID = uuid.New().String()
	}

	if opts != nil && opts.InstanceID != "" {
		values.Set("appId", opts.InstanceID)
	}

	if opts != nil && opts.Expiry != 0 {
		ttl := strconv.Itoa(int(opts.Expiry.Seconds()))
		values.Set("ttl", ttl)
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

func UnregisterGCM(ctx context.Context, authorizationEntity string, creds GCMCredentials, appID string) error {
	values := url.Values{}
	values.Set("app", "org.chromium.linux")
	values.Set("scope", "GCM")
	values.Set("X-scope", "GCM")
	values.Set("X-subtype", appID)
	values.Set("device", fmt.Sprint(creds.AndroidID))
	values.Set("gmsv", strings.Split(chromeVersion, ".")[0])
	values.Set("sender", authorizationEntity)
	values.Set("delete", "true")
	res, err := postRequest(ctx, registerURL, strings.NewReader(values.Encode()), func(header *http.Header) {
		header.Set("Content-Type", "application/x-www-form-urlencoded")
		header.Set("Authorization", fmt.Sprintf("AidLogin %d:%d", creds.AndroidID, creds.SecurityToken))
	})
	if err != nil {
		return errors.Wrap(err, "failed to unregister with GCM")
	}

	if res.StatusCode != http.StatusOK {
		return errors.New("failed to unregister with GCM")
	}

	return nil
}
