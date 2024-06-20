# go-push-receiver

[![GoDoc](https://godoc.org/github.com/beeper/push-receiver?status.svg)](https://godoc.org/github.com/beeper/push-receiver)
[![Go Report Card](https://goreportcard.com/badge/github.com/beeper/push-receiver)](https://goreportcard.com/report/github.com/beeper/push-receiver)
[![MIT License](https://img.shields.io/github/license/beeper/push-receiver)](LICENSE)
[![Github Actions](https://github.com/beeper/push-receiver/workflows/Go/badge.svg)](https://github.com/beeper/push-receiver/actions)

A library to subscribe to GCM/FCM and receive notifications.

This library was developed inspired by push-receiver (https://github.com/MatthieuLemoine/push-receiver/).

## Build

1. install protoc

```shell
brew install protobuf
```

2. build

```shell
$ go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
$ protoc -I=proto --go_out=pb/mcs proto/mcs.proto
$ protoc -I=proto --go_out=pb/checkin proto/checkin.proto
$ protoc -I=proto --go_out=pb/checkin proto/android_checkin.proto
$ go build
```

## License

MIT License

proto file is licensed by is The Chromium Authors. (BSD-style license)
(copied it from https://chromium.googlesource.com/chromium/chromium/+/trunk/google_apis/gcm/protocol/)
