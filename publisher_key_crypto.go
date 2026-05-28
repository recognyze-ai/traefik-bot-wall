package traefik_bot_wall

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const envPublisherKeyEncryptionKey = "BOTWALL_PUBLISHER_KEY_ENCRYPTION_KEY"

// loadPublisherEncryptionKey returns a 32-byte AES-256 key from env or file.
func loadPublisherEncryptionKey(keyFile string) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(envPublisherKeyEncryptionKey)); raw != "" {
		return decodeEncryptionKeyMaterial(raw)
	}
	keyFile = strings.TrimSpace(keyFile)
	if keyFile == "" {
		return nil, errors.New("publisher API key encryption key not configured (set " + envPublisherKeyEncryptionKey + " or publisherAPIKeyEncryptionKeyFile)")
	}
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read publisherAPIKeyEncryptionKeyFile: %w", err)
	}
	return decodeEncryptionKeyMaterial(strings.TrimSpace(string(data)))
}

func decodeEncryptionKeyMaterial(raw string) ([]byte, error) {
	if dec, err := base64.StdEncoding.DecodeString(raw); err == nil && len(dec) == 32 {
		return dec, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	if dec, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(dec) == 32 {
		return dec, nil
	}
	return nil, fmt.Errorf("encryption key must be 32 bytes or base64-encoded 32 bytes")
}

func encryptPublisherSecret(plaintext string, key []byte) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func decryptPublisherSecret(ciphertextB64 string, key []byte) (string, error) {
	if ciphertextB64 == "" {
		return "", nil
	}
	sealed, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:nonceSize], sealed[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// publisherKeyStateFile is the on-disk JSON shape (secret may be plaintext or secret_enc).
type publisherKeyStateFile struct {
	Secret       string `json:"secret,omitempty"`
	SecretEnc    string `json:"secret_enc,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	Name         string `json:"name,omitempty"`
	Status       string `json:"status,omitempty"`
	CreationDate string `json:"creation_date,omitempty"`
	Expiration   string `json:"expiration_date,omitempty"`
	RevokedKeyID string `json:"revoked_key_id,omitempty"`
	RotatedAt    string `json:"rotated_at,omitempty"`
	LastMetaSync string `json:"last_metadata_sync,omitempty"`
	NextRotation string `json:"next_rotation_at,omitempty"`
	LastRotError string `json:"last_rotation_error,omitempty"`
}

func decodePublisherKeyStateFile(raw []byte, encrypt bool, encKey []byte) (publisherKeyState, error) {
	var file publisherKeyStateFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return publisherKeyState{}, err
	}
	st := publisherKeyState{
		KeyID:        strings.TrimSpace(file.KeyID),
		Name:         strings.TrimSpace(file.Name),
		Status:       strings.TrimSpace(file.Status),
		CreationDate: strings.TrimSpace(file.CreationDate),
		Expiration:   strings.TrimSpace(file.Expiration),
		RevokedKeyID: strings.TrimSpace(file.RevokedKeyID),
		RotatedAt:    strings.TrimSpace(file.RotatedAt),
		LastMetaSync: strings.TrimSpace(file.LastMetaSync),
		NextRotation: strings.TrimSpace(file.NextRotation),
		LastRotError: strings.TrimSpace(file.LastRotError),
	}
	if enc := strings.TrimSpace(file.SecretEnc); enc != "" {
		if !encrypt || len(encKey) == 0 {
			return publisherKeyState{}, errors.New("state file has secret_enc but encryption is not configured")
		}
		secret, err := decryptPublisherSecret(enc, encKey)
		if err != nil {
			return publisherKeyState{}, fmt.Errorf("decrypt publisher API key state: %w", err)
		}
		st.Secret = secret
		return st, nil
	}
	st.Secret = strings.TrimSpace(file.Secret)
	return st, nil
}

func encodePublisherKeyStateFile(st publisherKeyState, encrypt bool, encKey []byte) ([]byte, error) {
	file := publisherKeyStateFile{
		KeyID:        st.KeyID,
		Name:         st.Name,
		Status:       st.Status,
		CreationDate: st.CreationDate,
		Expiration:   st.Expiration,
		RevokedKeyID: st.RevokedKeyID,
		RotatedAt:    st.RotatedAt,
		LastMetaSync: st.LastMetaSync,
		NextRotation: st.NextRotation,
		LastRotError: st.LastRotError,
	}
	if encrypt && len(encKey) > 0 {
		enc, err := encryptPublisherSecret(st.Secret, encKey)
		if err != nil {
			return nil, err
		}
		file.SecretEnc = enc
	} else {
		file.Secret = st.Secret
	}
	return json.Marshal(file)
}
