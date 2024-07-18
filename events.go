/*
 * Copyright (c) 2019 Zenichi Amano
 *
 * This file is part of go-push-receiver, which is MIT licensed.
 * See http://opensource.org/licenses/MIT
 */

package pushreceiver

import (
	"time"

	pb "github.com/beeper/push-receiver/pb/mcs"
)

// Event type.
type Event interface{}

// ConnectedEvent is connection event.
type ConnectedEvent struct {
	ServerTimestamp int64
}

// RetryEvent is disconnect event.
type RetryEvent struct {
	ErrorObj   error
	RetryAfter time.Duration
}

// DisconnectedEvent is disconnect event.
type DisconnectedEvent struct {
	ErrorObj error
}

// HeartbeatEvent is send/received heartbeat event.
type HeartbeatEvent struct {
	Send                 bool
	Ack                  bool
	Status               int64
	LastStreamIDReceived int32
}

// MessageEvent is receive message event.
type MessageEvent struct {
	PersistentID string        `json:"persistentId"`
	From         string        `json:"from"`
	To           string        `json:"to"`
	TTL          int32         `json:"ttl"`
	Sent         int64         `json:"sent"`
	AppData      []*pb.AppData `json:"app_data"`
	Token        string        `json:"token"`
	RegID        string        `json:"reg_id"`
	RawData      []byte        `json:"raw_data"`
	AppID        string        `json:"app_id"`
}

func newMessageEvent(data *pb.DataMessageStanza) *MessageEvent {
	return &MessageEvent{
		PersistentID: data.GetPersistentId(),
		From:         data.GetFrom(),
		To:           data.GetTo(),
		TTL:          data.GetTtl(),
		Sent:         data.GetSent(),
		AppData:      data.GetAppData(),
		Token:        data.GetToken(),
		RegID:        data.GetRegId(),
		RawData:      data.GetRawData(),
		AppID:        data.GetAppID(),
	}
}

// HeartbeatError is send heartbeat error.
type HeartbeatError struct {
	ErrorObj error
}

// UnauthorizedError is unauthorization error.
type UnauthorizedError struct {
	ErrorObj error
}
