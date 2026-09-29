package pushreceiver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type LegacyIIDConfig struct {
	PackageName      string `json:"package_name"`
	CertificateSHA1  string `json:"certificate_sha1"`
	FirebaseAppID    string `json:"firebase_app_id"`
	AppVersionCode   uint64 `json:"app_version_code"`
	AppVersionName   string `json:"app_version_name"`
	TargetSDKVersion uint32 `json:"target_sdk_version"`
	OSVersion        uint32 `json:"os_version"`
	GMSVersion       uint64 `json:"gms_version"`
	ClientVersion    string `json:"client_version"`
	Device           string `json:"device"`
	BuildID          string `json:"build_id"`
}

func (config LegacyIIDConfig) Validate() error {
	for _, value := range []string{config.PackageName, config.FirebaseAppID, config.ClientVersion, config.Device, config.BuildID} {
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("invalid legacy IID application metadata")
		}
	}
	certificate, err := hex.DecodeString(config.CertificateSHA1)
	if err != nil || len(certificate) != sha1.Size {
		return fmt.Errorf("invalid legacy IID application certificate")
	}
	if config.AppVersionCode == 0 || config.TargetSDKVersion == 0 || config.OSVersion == 0 || config.GMSVersion == 0 {
		return fmt.Errorf("invalid legacy IID application version")
	}
	return nil
}

func NewLegacyInstanceID() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	digest := sha1.Sum(publicKey)
	digest[0] = (digest[0] & 15) + 112
	return base64.RawURLEncoding.EncodeToString(digest[:8]), nil
}

func legacyIIDRegistrationValues(sender string, creds GCMCredentials, opts *GCMRegistrationOpts) (url.Values, error) {
	config := opts.LegacyIID
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if value, err := strconv.ParseUint(sender, 10, 64); err != nil || value == 0 {
		return nil, fmt.Errorf("invalid legacy IID sender")
	}
	iid, err := base64.RawURLEncoding.DecodeString(opts.InstanceID)
	if err != nil || len(iid) != 8 || iid[0]&0xf0 != 0x70 || base64.RawURLEncoding.EncodeToString(iid) != opts.InstanceID {
		return nil, fmt.Errorf("invalid legacy instance ID")
	}
	if creds.AndroidID == 0 || creds.SecurityToken == 0 {
		return nil, fmt.Errorf("missing legacy IID check-in credentials")
	}
	appVersion := strconv.FormatUint(config.AppVersionCode, 10)
	return url.Values{
		"app": {config.PackageName}, "cert": {strings.ToLower(config.CertificateSHA1)},
		"app_ver": {appVersion}, "target_ver": {strconv.FormatUint(uint64(config.TargetSDKVersion), 10)},
		"device": {strconv.FormatUint(creds.AndroidID, 10)}, "sender": {sender},
		"X-scope": {"*"}, "X-subtype": {sender}, "X-appid": {opts.InstanceID},
		"X-gmp_app_id": {config.FirebaseAppID}, "X-gmsv": {strconv.FormatUint(config.GMSVersion, 10)},
		"X-osv": {strconv.FormatUint(uint64(config.OSVersion), 10)}, "X-app_ver": {appVersion},
		"X-app_ver_name": {config.AppVersionName}, "X-cliv": {config.ClientVersion},
	}, nil
}
