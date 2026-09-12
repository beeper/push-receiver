package pushreceiver

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type AndroidBuild struct {
	Fingerprint   string `json:"fingerprint"`
	Hardware      string `json:"hardware"`
	Brand         string `json:"brand"`
	Bootloader    string `json:"bootloader"`
	Timestamp     uint64 `json:"timestamp"`
	GMSVersion    uint64 `json:"gms_version"`
	Device        string `json:"device"`
	SDKVersion    uint32 `json:"sdk_version"`
	Model         string `json:"model"`
	Manufacturer  string `json:"manufacturer"`
	Product       string `json:"product"`
	SecurityPatch string `json:"security_patch"`
}

type AndroidCheckInConfig struct {
	Build    AndroidBuild `json:"build"`
	Locale   string       `json:"locale"`
	TimeZone string       `json:"time_zone"`
}

type AndroidFCMConfig struct {
	PackageName                    string               `json:"package_name"`
	CertificateSHA1                string               `json:"certificate_sha1"`
	APIKey                         string               `json:"api_key"`
	FirebaseAppID                  string               `json:"firebase_app_id"`
	FirebaseProjectID              string               `json:"firebase_project_id"`
	FirebaseAppName                string               `json:"firebase_app_name,omitempty"`
	FirebaseInstallationSDKVersion string               `json:"firebase_installation_sdk_version"`
	FirebaseClientVersion          string               `json:"firebase_client_version"`
	FirebaseClient                 string               `json:"firebase_client,omitempty"`
	FirebaseClientLogType          string               `json:"firebase_client_log_type,omitempty"`
	AppVersionCode                 uint64               `json:"app_version_code"`
	AppVersionName                 string               `json:"app_version_name"`
	TargetSDKVersion               uint32               `json:"target_sdk_version"`
	CheckIn                        AndroidCheckInConfig `json:"checkin"`
}

func validMetadata(value string, required bool, maxLength int) bool {
	if required && value == "" || len(value) > maxLength {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func (config AndroidCheckInConfig) Validate() error {
	for _, value := range []string{
		config.Build.Fingerprint, config.Build.Hardware, config.Build.Brand,
		config.Build.Bootloader, config.Build.Device, config.Build.Model,
		config.Build.Manufacturer, config.Build.Product, config.Build.SecurityPatch,
		config.Locale, config.TimeZone,
	} {
		if !validMetadata(value, false, 1024) {
			return fmt.Errorf("invalid Android checkin metadata")
		}
	}
	return nil
}

func (config AndroidFCMConfig) Validate() error {
	for _, value := range []string{
		config.PackageName, config.APIKey, config.FirebaseAppID, config.FirebaseProjectID,
		config.FirebaseInstallationSDKVersion, config.FirebaseClientVersion,
	} {
		if !validMetadata(value, true, 1024) {
			return fmt.Errorf("invalid Android FCM application metadata")
		}
	}
	certificate, err := hex.DecodeString(config.CertificateSHA1)
	if err != nil || len(certificate) != sha1.Size {
		return fmt.Errorf("invalid Android application certificate fingerprint")
	}
	if strings.ContainsAny(config.FirebaseProjectID, "/\\?#%") || config.AppVersionCode == 0 ||
		config.TargetSDKVersion == 0 || config.CheckIn.Build.GMSVersion == 0 || config.CheckIn.Build.SDKVersion == 0 {
		return fmt.Errorf("invalid Android FCM project or version")
	}
	if !validMetadata(config.AppVersionName, false, 1024) || !validMetadata(config.FirebaseAppName, false, 1024) ||
		!validMetadata(config.FirebaseClient, false, 16384) ||
		!validMetadata(config.FirebaseClientLogType, false, 16) {
		return fmt.Errorf("invalid Android Firebase client metadata")
	}
	return config.CheckIn.Validate()
}

func androidRegistrationValues(sender string, creds GCMCredentials, config *AndroidFCMConfig, installation *FirebaseInstallation, requireAuth bool) (url.Values, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if value, err := strconv.ParseUint(sender, 10, 64); err != nil || value == 0 {
		return nil, fmt.Errorf("invalid Android FCM sender")
	}
	if creds.AndroidID == 0 || creds.SecurityToken == 0 || !validMetadata(creds.VersionInfo, true, 16384) {
		return nil, fmt.Errorf("incomplete Android checkin credentials")
	}
	if installation == nil || !validFirebaseInstallationID(installation.FID) || requireAuth && !installation.AuthTokenValid() {
		return nil, fmt.Errorf("Firebase installation authorization is missing or expiring")
	}
	appName := config.FirebaseAppName
	if appName == "" {
		appName = "[DEFAULT]"
	}
	appNameHash := sha1.Sum([]byte(appName))
	appVersion := strconv.FormatUint(config.AppVersionCode, 10)
	gmsVersion := strconv.FormatUint(config.CheckIn.Build.GMSVersion, 10)
	values := url.Values{
		"sender": {sender}, "X-subtype": {sender}, "X-scope": {"*"},
		"X-appid": {installation.FID},
		"app":     {config.PackageName}, "cert": {strings.ToLower(config.CertificateSHA1)},
		"device": {strconv.FormatUint(creds.AndroidID, 10)}, "info": {creds.VersionInfo},
		"app_ver": {appVersion}, "X-app_ver": {appVersion}, "X-app_ver_name": {config.AppVersionName},
		"gcm_ver": {gmsVersion}, "X-gmsv": {gmsVersion}, "plat": {"0"},
		"target_ver": {strconv.FormatUint(uint64(config.TargetSDKVersion), 10)},
		"X-osv":      {strconv.FormatUint(uint64(config.CheckIn.Build.SDKVersion), 10)},
		"X-cliv":     {config.FirebaseClientVersion}, "X-gmp_app_id": {config.FirebaseAppID},
		"X-firebase-app-name-hash": {base64.RawURLEncoding.EncodeToString(appNameHash[:])},
	}
	if installation.AuthTokenValid() {
		values.Set("X-Goog-Firebase-Installations-Auth", installation.AuthToken)
	}
	if config.FirebaseClient != "" {
		values.Set("X-Firebase-Client", config.FirebaseClient)
	}
	if config.FirebaseClientLogType != "" {
		values.Set("X-Firebase-Client-Log-Type", config.FirebaseClientLogType)
	}
	return values, nil
}

func (installation FirebaseInstallation) AuthTokenValid() bool {
	return validMetadata(installation.AuthToken, true, 16384) && time.Until(installation.AuthTokenExpiresAt) >= time.Hour
}
