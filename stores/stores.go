/*
Package stores acts as a layer between the internal representation of encrypted files and the encrypted files
themselves.

Subpackages implement serialization and deserialization to multiple formats.

This package defines the structure SOPS files should have and conversions to and from the internal representation. Part
of the purpose of this package is to make it easy to change the SOPS file format while remaining backwards-compatible.
*/
package stores

import (
	"time"

	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/pgp"
)

const (
	// SopsMetadataKey is the key used to store SOPS metadata at in SOPS encrypted files.
	SopsMetadataKey = "sops"
)

// SopsFile is a struct used by the stores as a helper to unmarshal the SOPS metadata
type SopsFile struct {
	// Metadata is a pointer so we can easily tell when the field is not present
	// in the SOPS file by checking for nil. This way we can show the user a
	// helpful error message indicating that the metadata wasn't found, instead
	// of showing a cryptic parsing error
	Metadata *Metadata `yaml:"sops" json:"sops" ini:"sops"`
}

// Metadata is stored in SOPS encrypted files, and it contains the information necessary to decrypt the file.
// This struct is just used for serialization, and SOPS uses another struct internally, sops.Metadata. It exists
// in order to allow the binary format to stay backwards compatible over time, but at the same time allow the internal
// representation SOPS uses to change over time.
type Metadata struct {
	ShamirThreshold           int         `yaml:"shamir_threshold,omitempty" json:"shamir_threshold,omitempty"`
	KeyGroups                 []keygroup  `yaml:"key_groups,omitempty" json:"key_groups,omitempty"`
	AgeKeys                   []agekey    `yaml:"age" json:"age"`
	LastModified              string      `yaml:"lastmodified" json:"lastmodified"`
	MessageAuthenticationCode string      `yaml:"mac" json:"mac"`
	PGPKeys                   []pgpkey    `yaml:"pgp" json:"pgp"`
	UnencryptedSuffix         string      `yaml:"unencrypted_suffix,omitempty" json:"unencrypted_suffix,omitempty"`
	EncryptedSuffix           string      `yaml:"encrypted_suffix,omitempty" json:"encrypted_suffix,omitempty"`
	UnencryptedRegex          string      `yaml:"unencrypted_regex,omitempty" json:"unencrypted_regex,omitempty"`
	EncryptedRegex            string      `yaml:"encrypted_regex,omitempty" json:"encrypted_regex,omitempty"`
	UnencryptedCommentRegex   string      `yaml:"unencrypted_comment_regex,omitempty" json:"unencrypted_comment_regex,omitempty"`
	EncryptedCommentRegex     string      `yaml:"encrypted_comment_regex,omitempty" json:"encrypted_comment_regex,omitempty"`
	MACOnlyEncrypted          bool        `yaml:"mac_only_encrypted,omitempty" json:"mac_only_encrypted,omitempty"`
	Version                   string      `yaml:"version" json:"version"`
}

type keygroup struct {
	PGPKeys           []pgpkey    `yaml:"pgp,omitempty" json:"pgp,omitempty"`
	AgeKeys           []agekey    `yaml:"age" json:"age"`
}

type pgpkey struct {
	CreatedAt        string `yaml:"created_at" json:"created_at"`
	EncryptedDataKey string `yaml:"enc" json:"enc"`
	Fingerprint      string `yaml:"fp" json:"fp"`
}

type agekey struct {
	Recipient        string `yaml:"recipient" json:"recipient"`
	EncryptedDataKey string `yaml:"enc" json:"enc"`
}

// MetadataFromInternal converts an internal SOPS metadata representation to a representation appropriate for storage
func MetadataFromInternal(sopsMetadata sops.Metadata) Metadata {
	var m Metadata
	m.LastModified = sopsMetadata.LastModified.Format(time.RFC3339)
	m.UnencryptedSuffix = sopsMetadata.UnencryptedSuffix
	m.EncryptedSuffix = sopsMetadata.EncryptedSuffix
	m.UnencryptedRegex = sopsMetadata.UnencryptedRegex
	m.EncryptedRegex = sopsMetadata.EncryptedRegex
	m.UnencryptedCommentRegex = sopsMetadata.UnencryptedCommentRegex
	m.EncryptedCommentRegex = sopsMetadata.EncryptedCommentRegex
	m.MessageAuthenticationCode = sopsMetadata.MessageAuthenticationCode
	m.MACOnlyEncrypted = sopsMetadata.MACOnlyEncrypted
	m.Version = sopsMetadata.Version
	m.ShamirThreshold = sopsMetadata.ShamirThreshold
	if len(sopsMetadata.KeyGroups) == 1 {
		group := sopsMetadata.KeyGroups[0]
		m.PGPKeys = pgpKeysFromGroup(group)
		m.AgeKeys = ageKeysFromGroup(group)
	} else {
		for _, group := range sopsMetadata.KeyGroups {
			m.KeyGroups = append(m.KeyGroups, keygroup{
				PGPKeys:           pgpKeysFromGroup(group),
				AgeKeys:           ageKeysFromGroup(group),
			})
		}
	}
	return m
}

func pgpKeysFromGroup(group sops.KeyGroup) (keys []pgpkey) {
	for _, key := range group {
		switch key := key.(type) {
		case *pgp.MasterKey:
			keys = append(keys, pgpkey{
				Fingerprint:      key.Fingerprint,
				EncryptedDataKey: key.EncryptedKey,
				CreatedAt:        key.CreationDate.Format(time.RFC3339),
			})
		}
	}
	return
}

func ageKeysFromGroup(group sops.KeyGroup) (keys []agekey) {
	for _, key := range group {
		switch key := key.(type) {
		case *age.MasterKey:
			keys = append(keys, agekey{
				Recipient:        key.Recipient,
				EncryptedDataKey: key.EncryptedKey,
			})
		}
	}
	return
}

// ToInternal converts a storage-appropriate Metadata struct to a SOPS internal representation
func (m *Metadata) ToInternal() (sops.Metadata, error) {
	lastModified, err := time.Parse(time.RFC3339, m.LastModified)
	if err != nil {
		return sops.Metadata{}, err
	}
	groups, err := m.internalKeygroups()
	if err != nil {
		return sops.Metadata{}, err
	}

	cryptRuleCount := 0
	if m.UnencryptedSuffix != "" {
		cryptRuleCount++
	}
	if m.EncryptedSuffix != "" {
		cryptRuleCount++
	}
	if m.UnencryptedRegex != "" {
		cryptRuleCount++
	}
	if m.EncryptedRegex != "" {
		cryptRuleCount++
	}
	if m.UnencryptedCommentRegex != "" {
		cryptRuleCount++
	}
	if m.EncryptedCommentRegex != "" {
		cryptRuleCount++
	}

	if cryptRuleCount > 1 {
		return sops.Metadata{}, fmt.Errorf("Cannot use more than one of encrypted_suffix, unencrypted_suffix, encrypted_regex, unencrypted_regex, encrypted_comment_regex, or unencrypted_comment_regex in the same file")
	}

	if cryptRuleCount == 0 {
		m.UnencryptedSuffix = sops.DefaultUnencryptedSuffix
	}
	return sops.Metadata{
		KeyGroups:                 groups,
		ShamirThreshold:           m.ShamirThreshold,
		Version:                   m.Version,
		MessageAuthenticationCode: m.MessageAuthenticationCode,
		UnencryptedSuffix:         m.UnencryptedSuffix,
		EncryptedSuffix:           m.EncryptedSuffix,
		UnencryptedRegex:          m.UnencryptedRegex,
		EncryptedRegex:            m.EncryptedRegex,
		UnencryptedCommentRegex:   m.UnencryptedCommentRegex,
		EncryptedCommentRegex:     m.EncryptedCommentRegex,
		MACOnlyEncrypted:          m.MACOnlyEncrypted,
		LastModified:              lastModified,
	}, nil
}

func internalGroupFrom(pgpKeys []pgpkey, ageKeys []agekey) (sops.KeyGroup, error) {
	var internalGroup sops.KeyGroup
	for _, pgpKey := range pgpKeys {
		k, err := pgpKey.toInternal()
		if err != nil {
			return nil, err
		}
		internalGroup = append(internalGroup, k)
	}
	for _, ageKey := range ageKeys {
		k, err := ageKey.toInternal()
		if err != nil {
			return nil, err
		}
		internalGroup = append(internalGroup, k)
	}
	return internalGroup, nil
}

func (m *Metadata) internalKeygroups() ([]sops.KeyGroup, error) {
	var internalGroups []sops.KeyGroup
	if len(m.PGPKeys) > 0 || len(m.AgeKeys) > 0 {
		internalGroup, err := internalGroupFrom(m.PGPKeys, m.AgeKeys)
		if err != nil {
			return nil, err
		}
		internalGroups = append(internalGroups, internalGroup)
		return internalGroups, nil
	} else if len(m.KeyGroups) > 0 {
		for _, group := range m.KeyGroups {
			internalGroup, err := internalGroupFrom(group.PGPKeys, group.AgeKeys)
			if err != nil {
				return nil, err
			}
			internalGroups = append(internalGroups, internalGroup)
		}
		return internalGroups, nil
	} else {
		return nil, fmt.Errorf("No keys found in file")
	}
}

func (pgpKey *pgpkey) toInternal() (*pgp.MasterKey, error) {
	creationDate, err := time.Parse(time.RFC3339, pgpKey.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &pgp.MasterKey{
		EncryptedKey: pgpKey.EncryptedDataKey,
		CreationDate: creationDate,
		Fingerprint:  pgpKey.Fingerprint,
	}, nil
}

func (ageKey *agekey) toInternal() (*age.MasterKey, error) {
	return &age.MasterKey{
		EncryptedKey: ageKey.EncryptedDataKey,
		Recipient:    ageKey.Recipient,
	}, nil
}

// ExampleComplexTree is an example sops.Tree object exhibiting complex relationships
var ExampleComplexTree = sops.Tree{
	Branches: sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{
				Key:   "hello",
				Value: `Welcome to SOPS! Edit this file as you please!`,
			},
			sops.TreeItem{
				Key:   "example_key",
				Value: "example_value",
			},
			sops.TreeItem{
				Key:   sops.Comment{Value: " Example comment"},
				Value: nil,
			},
			sops.TreeItem{
				Key: "example_array",
				Value: []interface{}{
					"example_value1",
					"example_value2",
				},
			},
			sops.TreeItem{
				Key:   "example_number",
				Value: 1234.56789,
			},
			sops.TreeItem{
				Key:   "example_booleans",
				Value: []interface{}{true, false},
			},
		},
	},
}

// ExampleSimpleTree is an example sops.Tree object exhibiting only simple relationships
// with only one nested branch and only simple string values
var ExampleSimpleTree = sops.Tree{
	Branches: sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{
				Key: "Welcome!",
				Value: sops.TreeBranch{
					sops.TreeItem{
						Key:   sops.Comment{Value: " This is an example file."},
						Value: nil,
					},
					sops.TreeItem{
						Key:   "hello",
						Value: "Welcome to SOPS! Edit this file as you please!",
					},
					sops.TreeItem{
						Key:   "example_key",
						Value: "example_value",
					},
				},
			},
		},
	},
}

// ExampleFlatTree is an example sops.Tree object exhibiting only simple relationships
// with no nested branches and only simple string values
var ExampleFlatTree = sops.Tree{
	Branches: sops.TreeBranches{
		sops.TreeBranch{
			sops.TreeItem{
				Key:   sops.Comment{Value: " This is an example file."},
				Value: nil,
			},
			sops.TreeItem{
				Key:   "hello",
				Value: "Welcome to SOPS! Edit this file as you please!",
			},
			sops.TreeItem{
				Key:   "example_key",
				Value: "example_value",
			},
			sops.TreeItem{
				Key:   "example_multiline",
				Value: "foo\nbar\nbaz",
			},
		},
	},
}

// HasSopsTopLevelKey returns true if the given branch has a top-level key called "sops".
func HasSopsTopLevelKey(branch sops.TreeBranch) bool {
	for _, b := range branch {
		if b.Key == SopsMetadataKey {
			return true
		}
	}
	return false
}
