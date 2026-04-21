package config

import (
        "crypto/ecdsa"
        "crypto/x509"
        "encoding/base64"
        "encoding/json"
        "encoding/pem"
        "fmt"
        "os"
)

// Config represents the application configuration structure, containing essential details such as keys, endpoints, and access tokens.
type Config struct {
        PrivateKey     string `json:"private_key"`      // Base64-encoded ECDSA private key
        EndpointV4     string `json:"endpoint_v4"`      // IPv4 address of the endpoint
        EndpointV6     string `json:"endpoint_v6"`      // IPv6 address of the endpoint
        EndpointH2V4   string `json:"endpoint_h2_v4"`   // IPv4 address used in HTTP/2 mode
        EndpointH2V6   string `json:"endpoint_h2_v6"`   // IPv6 address used in HTTP/2 mode
        EndpointPubKey string `json:"endpoint_pub_key"` // PEM-encoded ECDSA public key of the endpoint to verify against
        License        string `json:"license"`          // Application license key
        ID             string `json:"id"`               // Device unique identifier
        AccessToken    string `json:"access_token"`     // Authentication token for API access
        IPv4           string `json:"ipv4"`             // Assigned IPv4 address
        IPv6           string `json:"ipv6"`             // Assigned IPv6 address
}

// AppConfig holds the global application configuration.
var AppConfig Config

// ConfigLoaded indicates whether the configuration has been successfully loaded.
var ConfigLoaded bool

// LoadConfig loads the application configuration from a JSON file.
//
// Parameters:
//   - configPath: string - The path to the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be loaded or parsed.
func LoadConfig(configPath string) error {
        file, err := os.Open(configPath)
        if err != nil {
                return fmt.Errorf("failed to open config file: %v", err)
        }
        defer file.Close()

        decoder := json.NewDecoder(file)
        if err := decoder.Decode(&AppConfig); err != nil {
                return fmt.Errorf("failed to decode config file: %v", err)
        }

        ConfigLoaded = true

        return nil
}

// SaveConfig writes the current application configuration to a prettified JSON file.
//
// The file is created with mode 0600 (owner read/write only) because it
// contains the device's ECDSA private key and the WARP access token. If the
// file already exists, its permissions are tightened to 0600 defensively.
//
// Parameters:
//   - configPath: string - The path to save the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be written.
func (*Config) SaveConfig(configPath string) error {
        // O_CREATE|O_TRUNC|O_WRONLY with 0600 ensures the secrets file is not
        // world- or group-readable on first creation. umask still applies to
        // the create mode, so we explicitly Chmod afterwards in case the file
        // already existed with looser permissions from an older version.
        file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
        if err != nil {
                return fmt.Errorf("failed to create config file: %v", err)
        }
        defer file.Close()

        if err := os.Chmod(configPath, 0600); err != nil {
                // Non-fatal on platforms where chmod is best-effort (e.g. Windows),
                // but worth surfacing as a warning by returning the error so the
                // caller can decide.
                return fmt.Errorf("failed to set config file permissions to 0600: %v", err)
        }

        encoder := json.NewEncoder(file)
        encoder.SetIndent("", "  ")
        if err := encoder.Encode(AppConfig); err != nil {
                return fmt.Errorf("failed to encode config file: %v", err)
        }

        return nil
}

// GetEcPrivateKey retrieves the ECDSA private key from the stored Base64-encoded string.
//
// Returns:
//   - *ecdsa.PrivateKey: The parsed ECDSA private key.
//   - error: An error if decoding or parsing the private key fails.
func (*Config) GetEcPrivateKey() (*ecdsa.PrivateKey, error) {
        privKeyB64, err := base64.StdEncoding.DecodeString(AppConfig.PrivateKey)
        if err != nil {
                return nil, fmt.Errorf("failed to decode private key: %v", err)
        }

        privKey, err := x509.ParseECPrivateKey(privKeyB64)
        if err != nil {
                return nil, fmt.Errorf("failed to parse private key: %v", err)
        }

        return privKey, nil
}

// GetEcEndpointPublicKey retrieves the ECDSA public key from the stored PEM-encoded string.
//
// Returns:
//   - *ecdsa.PublicKey: The parsed ECDSA public key.
//   - error: An error if decoding or parsing the public key fails.
func (*Config) GetEcEndpointPublicKey() (*ecdsa.PublicKey, error) {
        endpointPubKeyB64, _ := pem.Decode([]byte(AppConfig.EndpointPubKey))
        if endpointPubKeyB64 == nil {
                return nil, fmt.Errorf("failed to decode endpoint public key")
        }

        pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64.Bytes)
        if err != nil {
                return nil, fmt.Errorf("failed to parse public key: %v", err)
        }

        ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
        if !ok {
                return nil, fmt.Errorf("failed to assert public key as ECDSA")
        }

        return ecPubKey, nil
}
