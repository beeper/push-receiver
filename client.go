/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of go-push-receiver, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

// Package pushreceiver is Push Message Receiver library from FCM.
package pushreceiver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	pb "github.com/beeper/push-receiver/pb/mcs"
	"github.com/pkg/errors"
)

// httpClient defines the minimal interface needed for an http.Client to be implemented.
type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type MCSClient struct {
	log                  ilogger
	httpClient           httpClient
	tlsConfig            *tls.Config
	creds                *GCMCredentials
	dialer               *net.Dialer
	backoff              *Backoff
	heartbeat            *Heartbeat
	receivedPersistentID []string
	retryDisabled        bool
	Events               chan Event
}

// New returns a new FCM push receive client instance.
func New(options ...ClientOption) *MCSClient {
	c := &MCSClient{
		Events: make(chan Event, 50),
	}

	for _, option := range options {
		option(c)
	}

	// set defaults
	if c.backoff == nil {
		c.backoff = NewBackoff(defaultBackoffBase*time.Second, defaultBackoffMax*time.Second)
	}
	if c.heartbeat == nil {
		c.heartbeat = newHeartbeat(
			WithClientInterval(defaultHeartbeatPeriod * time.Minute),
		)
	}
	if c.tlsConfig == nil {
		c.tlsConfig = &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS13,
		}
	}
	if c.dialer == nil {
		c.dialer = &net.Dialer{
			Timeout:       defaultDialTimeout * time.Second,
			KeepAlive:     defaultKeepAlive * time.Minute,
			FallbackDelay: 30 * time.Millisecond,
		}
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: c.tlsConfig,
			},
		}
	}
	if c.log == nil {
		c.log = &discard{}
	}

	return c
}

func (c *MCSClient) Listen(ctx context.Context) {
	defer close(c.Events)

	for ctx.Err() == nil {
		// reset retry count when connection success
		c.backoff.reset()

		err := c.tryToConnect(ctx)
		if err != nil {
			if errors.Is(err, ErrGcmAuthorization) {
				c.Events <- &UnauthorizedError{err}
				c.creds = nil
			}
			if c.retryDisabled {
				return
			}
			// retry
			sleepDuration := c.backoff.duration()
			c.Events <- &RetryEvent{err, sleepDuration}
			tick := time.After(sleepDuration)
			select {
			case <-tick:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (c *MCSClient) tryToConnect(ctx context.Context) error {
	conn, err := tls.DialWithDialer(c.dialer, "tcp", mtalkServer, c.tlsConfig)
	if err != nil {
		return errors.Wrap(err, "dial failed to FCM")
	}
	defer conn.Close()

	mcs := newMCS(conn, c.log, c.creds, c.heartbeat, c.Events)
	defer mcs.disconnect()

	err = mcs.SendLoginPacket(c.receivedPersistentID)
	if err != nil {
		return errors.Wrap(err, "send login packet failed")
	}

	// start heartbeat
	go c.heartbeat.start(ctx, mcs)

	select {
	case err := <-c.asyncPerformRead(mcs):
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *MCSClient) asyncPerformRead(mcs *mcs) <-chan error {
	ch := make(chan error)
	go func() {
		defer close(ch)
		ch <- c.performRead(mcs)
	}()
	return ch
}

func (c *MCSClient) performRead(mcs *mcs) error {
	// receive version
	err := mcs.ReceiveVersion()
	if err != nil {
		return errors.Wrap(err, "receive version failed")
	}

	for {
		// receive tag
		data, err := mcs.PerformReadTag()
		if err != nil {
			return errors.Wrap(err, "receive tag failed")
		}
		if data == nil {
			return ErrFcmNotEnoughData
		}

		err = c.onDataMessage(data)
		if err != nil {
			return errors.Wrap(err, "process data message failed")
		}
	}
}

func (c *MCSClient) onDataMessage(tagData interface{}) error {
	switch data := tagData.(type) {
	case *pb.LoginResponse:
		c.receivedPersistentID = nil
		c.Events <- &ConnectedEvent{data.GetServerTimestamp()}
	case *pb.DataMessageStanza:
		// To avoid error loops, last streamID is notified even when an error occurs.
		c.receivedPersistentID = append(c.receivedPersistentID, data.GetPersistentId())
		c.Events <- newMessageEvent(data)
	}
	return nil
}
