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
	AppID        string
	InstanceID   string
	Expiry       time.Duration
	Android      *AndroidFCMConfig
	Installation *FirebaseInstallation
}

func setGCMAppID(values url.Values, appID string) {
	if len(appID) == 32 && strings.Trim(appID, "abcdefghijklmnop") == "" {
		values.Set("app", appID)
	} else {
		values.Set("app", "org.chromium.linux")
		values.Set("X-subtype", appID)
	}
}

func NewGCMAppID(authorizationEntity string) string {
	if _, err := strconv.ParseUint(authorizationEntity, 10, 64); err != nil {
		return "wp:" + strings.ToUpper(uuid.New().String())
	}
	id := uuid.New()
	var encoded [32]byte
	for i, b := range id {
		encoded[i*2] = 'a' + b>>4
		encoded[i*2+1] = 'a' + b&15
	}
	return string(encoded[:])
}

func RegisterGCM(ctx context.Context, authorizationEntity string, creds GCMCredentials, opts *GCMRegistrationOpts) (*FCMCredentials, error) {
	values := url.Values{}

	var appID string
	if opts != nil && opts.AppID != "" {
		appID = opts.AppID
	} else {
		appID = NewGCMAppID(authorizationEntity)
	}

	endpoint := registerURL
	post := postRequest
	if opts != nil && opts.Android != nil {
		var err error
		values, err = androidRegistrationValues(authorizationEntity, creds, opts.Android, opts.Installation, true)
		if err != nil {
			return nil, err
		}
		endpoint = "https://android.apis.google.com/c2dm/register3"
		post = postAndroidRequest
	} else {
		if opts != nil && opts.InstanceID != "" {
			values.Set("appid", opts.InstanceID)
		}
		if opts != nil && opts.Expiry != 0 {
			ttl := strconv.Itoa(int(opts.Expiry.Seconds()))
			values.Set("ttl", ttl)
		}
		setGCMAppID(values, appID)
		values.Set("scope", "GCM")
		values.Set("X-scope", "GCM")
		values.Set("device", fmt.Sprint(creds.AndroidID))
		values.Set("gmsv", strings.Split(chromeVersion, ".")[0])
		values.Set("sender", authorizationEntity)
	}

	res, err := post(ctx, endpoint, strings.NewReader(values.Encode()), func(header *http.Header) {
		header.Set("Content-Type", "application/x-www-form-urlencoded")
		header.Set("Authorization", fmt.Sprintf("AidLogin %d:%d", creds.AndroidID, creds.SecurityToken))
	})
	if err != nil {
		return nil, errors.Wrap(err, "request GCM register")
	}
	subscription, err := parseGCMResponse(res, opts != nil && opts.Android != nil)
	if err != nil {
		return nil, errors.Wrap(err, "read GCM register response")
	}
	token := subscription.Get("token")
	if token == "" {
		return nil, errors.New("GCM register response missing token")
	}

	return &FCMCredentials{
		GCM:   creds,
		Token: token,
		AppID: appID,
	}, nil
}

func UnregisterGCM(ctx context.Context, authorizationEntity string, creds GCMCredentials, appID string, options ...*GCMRegistrationOpts) error {
	if len(options) > 1 {
		return errors.New("multiple GCM unregistration options")
	}
	var opts *GCMRegistrationOpts
	if len(options) == 1 {
		opts = options[0]
	}
	android := opts != nil && opts.Android != nil
	values := url.Values{}
	endpoint := registerURL
	post := postRequest
	if android {
		var err error
		values, err = androidRegistrationValues(authorizationEntity, creds, opts.Android, opts.Installation, false)
		if err != nil {
			return err
		}
		values.Set("X-delete", "1")
		endpoint = "https://android.apis.google.com/c2dm/register3"
		post = postAndroidRequest
	} else {
		setGCMAppID(values, appID)
		values.Set("scope", "GCM")
		values.Set("X-scope", "GCM")
		values.Set("device", fmt.Sprint(creds.AndroidID))
		values.Set("gmsv", strings.Split(chromeVersion, ".")[0])
		values.Set("sender", authorizationEntity)
		values.Set("delete", "true")
	}
	res, err := post(ctx, endpoint, strings.NewReader(values.Encode()), func(header *http.Header) {
		header.Set("Content-Type", "application/x-www-form-urlencoded")
		header.Set("Authorization", fmt.Sprintf("AidLogin %d:%d", creds.AndroidID, creds.SecurityToken))
	})
	if err != nil {
		return errors.Wrap(err, "failed to unregister with GCM")
	}

	response, err := parseGCMResponse(res, android)
	if err != nil {
		return errors.Wrap(err, "read GCM unregister response")
	}
	if android {
		if !response.Has("deleted") {
			return errors.New("Android FCM unregister response missing confirmation")
		}
	} else if response.Get("token") == "" && response.Get("deleted") != appID {
		return errors.New("GCM unregister response missing confirmation")
	}

	return nil
}

func parseGCMResponse(res *http.Response, android bool) (url.Values, error) {
	if android {
		defer res.Body.Close()
	} else {
		defer closeResponse(res)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", res.StatusCode)
	}
	var body io.Reader = res.Body
	if android {
		body = io.LimitReader(body, 65537)
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if android && len(data) > 65536 {
		return nil, errors.New("GCM response too large")
	}
	var values url.Values
	if android {
		values = url.Values{}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			key, value, found := strings.Cut(line, "=")
			if !found || key == "" {
				return nil, errors.New("invalid Android FCM response")
			}
			values.Set(key, value)
		}
	} else {
		values, err = url.ParseQuery(string(data))
		if err != nil {
			return nil, err
		}
	}
	if message := values.Get("Error"); message != "" {
		if android && (len(message) > 128 || strings.Trim(message, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "") {
			return nil, errors.New("GCM response contains an invalid error code")
		}
		return nil, GCMError(message)
	}
	return values, nil
}
