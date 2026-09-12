package pushreceiver

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type FirebaseInstallation struct {
	FID                string    `json:"fid"`
	RefreshToken       string    `json:"refresh_token"`
	AuthToken          string    `json:"auth_token"`
	AuthTokenExpiresAt time.Time `json:"auth_token_expires_at"`
}

type FirebaseError int

func (err FirebaseError) Error() string {
	return fmt.Sprintf("firebase installation HTTP status %d", int(err))
}

var ErrFirebaseInstallationAuth = errors.New("firebase installation authorization rejected")

func NewFirebaseInstallationID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	var data [17]byte
	copy(data[:16], id[:])
	data[16] = data[0]
	data[0] = data[0]&15 | 112
	return base64.RawURLEncoding.EncodeToString(data[:])[:22], nil
}

func validFirebaseInstallationID(fid string) bool {
	return len(fid) == 22 && strings.Trim(fid, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}

type firebaseAuthToken struct {
	Token     string `json:"token"`
	ExpiresIn string `json:"expiresIn"`
}

func (token firebaseAuthToken) expiration(issuedAt time.Time) (time.Time, error) {
	seconds, err := strconv.ParseUint(strings.TrimSuffix(token.ExpiresIn, "s"), 10, 32)
	if err != nil || !strings.HasSuffix(token.ExpiresIn, "s") || seconds == 0 || !validMetadata(token.Token, true, 16384) {
		return time.Time{}, fmt.Errorf("invalid Firebase installation auth response")
	}
	return issuedAt.Add(time.Duration(seconds) * time.Second), nil
}

func CreateFirebaseInstallation(ctx context.Context, config *AndroidFCMConfig, fid string) (*FirebaseInstallation, error) {
	if config == nil {
		return nil, fmt.Errorf("missing Android FCM configuration")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !validFirebaseInstallationID(fid) {
		return nil, fmt.Errorf("invalid Firebase installation ID")
	}
	body := map[string]string{
		"fid": fid, "appId": config.FirebaseAppID, "authVersion": "FIS_v2", "sdkVersion": config.FirebaseInstallationSDKVersion,
	}
	var result struct {
		FID          string            `json:"fid"`
		RefreshToken string            `json:"refreshToken"`
		AuthToken    firebaseAuthToken `json:"authToken"`
	}
	issuedAt := time.Now()
	if err := firebaseRequest(ctx, config, "", "", body, &result); err != nil {
		return nil, err
	}
	if !validFirebaseInstallationID(result.FID) || !validMetadata(result.RefreshToken, true, 16384) {
		return nil, fmt.Errorf("incomplete Firebase installation response")
	}
	expiration, err := result.AuthToken.expiration(issuedAt)
	if err != nil {
		return nil, err
	}
	return &FirebaseInstallation{result.FID, result.RefreshToken, result.AuthToken.Token, expiration}, nil
}

func RefreshFirebaseInstallation(ctx context.Context, config *AndroidFCMConfig, installation FirebaseInstallation) (*FirebaseInstallation, error) {
	if config == nil {
		return nil, fmt.Errorf("missing Android FCM configuration")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !validFirebaseInstallationID(installation.FID) || !validMetadata(installation.RefreshToken, true, 16384) {
		return nil, fmt.Errorf("incomplete Firebase installation credentials")
	}
	body := map[string]any{"installation": map[string]string{"sdkVersion": config.FirebaseInstallationSDKVersion}}
	var token firebaseAuthToken
	issuedAt := time.Now()
	if err := firebaseRequest(ctx, config, installation.FID, installation.RefreshToken, body, &token); err != nil {
		var status FirebaseError
		if errors.As(err, &status) && (status == http.StatusUnauthorized || status == http.StatusNotFound) {
			return nil, fmt.Errorf("%w: %w", ErrFirebaseInstallationAuth, err)
		}
		return nil, err
	}
	expiration, err := token.expiration(issuedAt)
	if err != nil {
		return nil, err
	}
	installation.AuthToken = token.Token
	installation.AuthTokenExpiresAt = expiration
	return &installation, nil
}

func firebaseRequest(ctx context.Context, config *AndroidFCMConfig, fid, refreshToken string, body, result any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode Firebase installation request")
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write(data); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	endpoint := "https://firebaseinstallations.googleapis.com/v1/projects/" + url.PathEscape(config.FirebaseProjectID) + "/installations"
	if fid != "" {
		endpoint += "/" + url.PathEscape(fid) + "/authTokens:generate"
	}
	response, err := postAndroidRequest(ctx, endpoint, &compressed, func(header *http.Header) {
		header.Set("Content-Type", "application/json")
		header.Set("Accept", "application/json")
		header.Set("Content-Encoding", "gzip")
		header.Set("Cache-Control", "no-cache")
		header.Set("X-Android-Package", config.PackageName)
		header.Set("X-Android-Cert", strings.ToUpper(config.CertificateSHA1))
		header.Set("X-Goog-Api-Key", config.APIKey)
		if refreshToken != "" {
			header.Set("Authorization", "FIS_v2 "+refreshToken)
		}
	})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return FirebaseError(response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return fmt.Errorf("read Firebase installation response: %w", err)
	}
	if len(data) > 65536 || json.Unmarshal(data, result) != nil {
		return fmt.Errorf("invalid Firebase installation response")
	}
	return nil
}

func postAndroidRequest(ctx context.Context, endpoint string, body io.Reader, headerSetter func(*http.Header)) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("create Android registration request")
	}
	headerSetter(&request.Header)
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		return nil, fmt.Errorf("android registration request failed: %w", err)
	}
	return response, nil
}
