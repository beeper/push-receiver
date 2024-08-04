/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of go-push-receiver, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package pushreceiver

import (
	"crypto/tls"
	"net"
)

// ClientOption type
type ClientOption func(*MCSClient)

// WithLogger is logger setter
func WithLogger(logger logger) ClientOption {
	return func(client *MCSClient) {
		client.log = internalLog{logger}
	}
}

// WithCreds is credentials setter
func WithCreds(creds *GCMCredentials) ClientOption {
	return func(client *MCSClient) {
		client.creds = creds
	}
}

// WithReceivedPersistentID is received persistentId list setter
func WithReceivedPersistentID(ids []string) ClientOption {
	return func(client *MCSClient) {
		client.receivedPersistentID = ids
	}
}

// WithHTTPClient is http.Client setter
func WithHTTPClient(c httpClient) ClientOption {
	return func(client *MCSClient) {
		client.httpClient = c
	}
}

// WithTLSConfig is tls.Config setter
func WithTLSConfig(c *tls.Config) ClientOption {
	return func(client *MCSClient) {
		client.tlsConfig = c
	}
}

// WithBackoff is Backoff setter
func WithBackoff(b *Backoff) ClientOption {
	return func(client *MCSClient) {
		client.backoff = b
	}
}

// WithHeartbeat is Heartbeat setter
func WithHeartbeat(options ...HeartbeatOption) ClientOption {
	return func(client *MCSClient) {
		client.heartbeat = newHeartbeat(options...)
	}
}

// WithDialer is net.Dialer setter
func WithDialer(dialer *net.Dialer) ClientOption {
	return func(client *MCSClient) {
		client.dialer = dialer
	}
}

// WithRetry configures whether to retry when an error occurs.
func WithRetry(retry bool) ClientOption {
	return func(client *MCSClient) {
		client.retryDisabled = !retry
	}
}

func WithMaxUnackedIDs(maxIDs int) ClientOption {
	return func(client *MCSClient) {
		client.maxUnackedIDs = maxIDs
	}
}
