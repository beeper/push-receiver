package pushreceiver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	pb "github.com/beeper/push-receiver/pb/checkin"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

func CheckIn(ctx context.Context, opt *GCMCredentials, options ...*AndroidCheckInConfig) (*GCMCredentials, error) {
	if opt == nil {
		opt = &GCMCredentials{}
	}
	if len(options) > 1 {
		return nil, fmt.Errorf("multiple Android checkin configurations")
	}
	var config *AndroidCheckInConfig
	if len(options) == 1 {
		config = options[0]
	}
	if config != nil {
		if err := config.Validate(); err != nil {
			return nil, err
		}
	}
	resp, err := checkin(ctx, opt, config)
	if err != nil {
		return nil, err
	}

	creds := *opt
	if resp.AndroidId != nil {
		creds.AndroidID = resp.GetAndroidId()
	}
	if resp.SecurityToken != nil {
		creds.SecurityToken = resp.GetSecurityToken()
	}
	if resp.VersionInfo != nil {
		creds.VersionInfo = resp.GetVersionInfo()
	}
	if creds.AndroidID == 0 || creds.SecurityToken == 0 || config != nil && creds.VersionInfo == "" {
		return nil, fmt.Errorf("incomplete GCM checkin response")
	}

	return &creds, nil
}

func checkin(ctx context.Context, opt *GCMCredentials, config *AndroidCheckInConfig) (*pb.AndroidCheckinResponse, error) {
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
	endpoint := checkinURL
	post := postRequest
	if config != nil {
		build := config.Build
		optionalString := func(value string) *string {
			if value == "" {
				return nil
			}
			return &value
		}
		r.Checkin = &pb.AndroidCheckinProto{
			UserNumber: proto.Int32(0),
			Build: &pb.AndroidBuildProto{
				Fingerprint: optionalString(build.Fingerprint), Hardware: optionalString(build.Hardware),
				Brand: optionalString(build.Brand), Bootloader: optionalString(build.Bootloader),
				Device: optionalString(build.Device), Model: optionalString(build.Model),
				Manufacturer: optionalString(build.Manufacturer), Product: optionalString(build.Product),
				SecurityPatch: optionalString(build.SecurityPatch),
			},
		}
		if build.Timestamp != 0 {
			r.Checkin.Build.Timestamp = proto.Uint64(build.Timestamp)
		}
		if build.GMSVersion != 0 {
			r.Checkin.Build.GmsVersion = proto.Uint64(build.GMSVersion)
		}
		if build.SDKVersion != 0 {
			r.Checkin.Build.SdkVersion = proto.Uint32(build.SDKVersion)
		}
		r.Locale = optionalString(config.Locale)
		r.TimeZone = optionalString(config.TimeZone)
		endpoint = "https://android.googleapis.com/checkin"
		post = postAndroidRequest
	}

	message, err := proto.Marshal(r)
	if err != nil {
		return nil, errors.Wrap(err, "marshal GCM checkin request")
	}

	res, err := post(ctx, endpoint, bytes.NewReader(message), func(header *http.Header) {
		header.Set("Content-Type", "application/x-protobuf")
	})
	if err != nil {
		return nil, errors.Wrap(err, "request GCM checkin")
	}
	if config != nil {
		defer res.Body.Close()
	} else {
		defer closeResponse(res)
	}

	// unauthorized error
	if res.StatusCode == http.StatusUnauthorized {
		return nil, ErrGcmAuthorization
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		if config != nil {
			return nil, fmt.Errorf("Android checkin HTTP status %d", res.StatusCode)
		}
		return nil, errors.Errorf("server error: %s", res.Status)
	}
	var body io.Reader = res.Body
	if config != nil {
		body = io.LimitReader(body, 4*1024*1024+1)
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, errors.Wrap(err, "read GCM checkin response")
	}
	if config != nil && len(data) > 4*1024*1024 {
		return nil, fmt.Errorf("GCM checkin response too large")
	}

	var responseProto pb.AndroidCheckinResponse
	err = proto.Unmarshal(data, &responseProto)
	if err != nil {
		return nil, errors.Wrapf(err, "unmarshal GCM checkin response")
	}
	return &responseProto, nil
}
