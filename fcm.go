/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of go-push-receiver, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package pushreceiver

// FCMCredentials is Credentials for FCM
type FCMCredentials struct {
	GCM   GCMCredentials `json:"gcm"`
	AppID string         `json:"appId"` // device identifier
	Token string         `json:"token"` // push token for clients to register with
}

type GCMCredentials struct {
	AndroidID     uint64 `json:"androidId"`
	SecurityToken uint64 `json:"securityToken"`
}
