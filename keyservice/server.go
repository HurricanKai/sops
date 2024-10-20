package keyservice

import (
	"fmt"

	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/pgp"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server is a key service server that uses SOPS MasterKeys to fulfill requests
type Server struct {
	// Prompt indicates whether the server should prompt before decrypting or encrypting data
	Prompt bool
}

func (ks *Server) encryptWithPgp(key *PgpKey, plaintext []byte) ([]byte, error) {
	pgpKey := pgp.NewMasterKeyFromFingerprint(key.Fingerprint)
	err := pgpKey.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return []byte(pgpKey.EncryptedKey), nil
}

func (ks *Server) encryptWithAge(key *AgeKey, plaintext []byte) ([]byte, error) {
	ageKey := age.MasterKey{
		Recipient: key.Recipient,
	}

	if err := ageKey.Encrypt(plaintext); err != nil {
		return nil, err
	}

	return []byte(ageKey.EncryptedKey), nil
}

func (ks *Server) decryptWithPgp(key *PgpKey, ciphertext []byte) ([]byte, error) {
	pgpKey := pgp.NewMasterKeyFromFingerprint(key.Fingerprint)
	pgpKey.EncryptedKey = string(ciphertext)
	plaintext, err := pgpKey.Decrypt()
	return []byte(plaintext), err
}

func (ks *Server) decryptWithAge(key *AgeKey, ciphertext []byte) ([]byte, error) {
	ageKey := age.MasterKey{
		Recipient: key.Recipient,
	}
	ageKey.EncryptedKey = string(ciphertext)
	plaintext, err := ageKey.Decrypt()
	return []byte(plaintext), err
}

// Encrypt takes an encrypt request and encrypts the provided plaintext with the provided key, returning the encrypted
// result
func (ks Server) Encrypt(ctx context.Context,
	req *EncryptRequest) (*EncryptResponse, error) {
	key := req.Key
	var response *EncryptResponse
	switch k := key.KeyType.(type) {
	case *Key_PgpKey:
		ciphertext, err := ks.encryptWithPgp(k.PgpKey, req.Plaintext)
		if err != nil {
			return nil, err
		}
		response = &EncryptResponse{
			Ciphertext: ciphertext,
		}
	case *Key_AgeKey:
		ciphertext, err := ks.encryptWithAge(k.AgeKey, req.Plaintext)
		if err != nil {
			return nil, err
		}
		response = &EncryptResponse{
			Ciphertext: ciphertext,
		}
	case nil:
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	default:
		return nil, status.Errorf(codes.NotFound, "Unknown key type")
	}
	if ks.Prompt {
		err := ks.prompt(key, "encrypt")
		if err != nil {
			return nil, err
		}
	}
	return response, nil
}

func keyToString(key *Key) string {
	switch k := key.KeyType.(type) {
	case *Key_PgpKey:
		return fmt.Sprintf("PGP key with fingerprint %s", k.PgpKey.Fingerprint)
	default:
		return "Unknown key type"
	}
}

func (ks Server) prompt(key *Key, requestType string) error {
	keyString := keyToString(key)
	var response string
	for response != "y" && response != "n" {
		fmt.Printf("\nReceived %s request using %s. Respond to request? (y/n): ", requestType, keyString)
		_, err := fmt.Scanln(&response)
		if err != nil {
			return err
		}
	}
	if response == "n" {
		return status.Errorf(codes.PermissionDenied, "Request rejected by user")
	}
	return nil
}

// Decrypt takes a decrypt request and decrypts the provided ciphertext with the provided key, returning the decrypted
// result
func (ks Server) Decrypt(ctx context.Context,
	req *DecryptRequest) (*DecryptResponse, error) {
	key := req.Key
	var response *DecryptResponse
	switch k := key.KeyType.(type) {
	case *Key_PgpKey:
		plaintext, err := ks.decryptWithPgp(k.PgpKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &DecryptResponse{
			Plaintext: plaintext,
		}
	case *Key_AgeKey:
		plaintext, err := ks.decryptWithAge(k.AgeKey, req.Ciphertext)
		if err != nil {
			return nil, err
		}
		response = &DecryptResponse{
			Plaintext: plaintext,
		}
	case nil:
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	default:
		return nil, status.Errorf(codes.NotFound, "Unknown key type")
	}
	if ks.Prompt {
		err := ks.prompt(key, "decrypt")
		if err != nil {
			return nil, err
		}
	}
	return response, nil
}
