package pushreceiver

import (
	"bytes"
	"context"
	"io"
	"net/http"

	pb "github.com/crow-misia/go-push-receiver/pb/checkin"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

func CheckIn(ctx context.Context, opt *GCMCredentials) (*pb.AndroidCheckinResponse, error) {
	id := int64(opt.AndroidID)
	r := &pb.AndroidCheckinRequest{
		Checkin: &pb.AndroidCheckinProto{
			ChromeBuild: &pb.ChromeBuildProto{
				Platform:      pb.ChromeBuildProto_PLATFORM_LINUX.Enum(),
				ChromeVersion: proto.String(chromeVersion),
				Channel:       pb.ChromeBuildProto_CHANNEL_STABLE.Enum(),
			},
			Type:       pb.DeviceType_DEVICE_CHROME_BROWSER.Enum(),
			UserNumber: proto.Int32(0),
		},
		Fragment:         proto.Int32(0),
		Version:          proto.Int32(3),
		UserSerialNumber: proto.Int32(0),
		Id:               &id,
		SecurityToken:    &opt.SecurityToken,
	}

	message, err := proto.Marshal(r)
	if err != nil {
		return nil, errors.Wrap(err, "marshal GCM checkin request")
	}

	res, err := postRequest(ctx, checkinURL, bytes.NewReader(message), func(header *http.Header) {
		header.Set("Content-Type", "application/x-protobuf")
	})
	if err != nil {
		return nil, errors.Wrap(err, "request GCM checkin")
	}
	defer closeResponse(res)

	// unauthorized error
	if res.StatusCode == http.StatusUnauthorized {
		return nil, ErrGcmAuthorization
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, errors.Errorf("server error: %s", res.Status)
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read GCM checkin response")
	}

	var responseProto pb.AndroidCheckinResponse
	err = proto.Unmarshal(data, &responseProto)
	if err != nil {
		return nil, errors.Wrapf(err, "unmarshal GCM checkin response")
	}
	return &responseProto, nil
}
