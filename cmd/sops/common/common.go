package common

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/cmd/sops/codes"
	. "github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/dotenv"
	"github.com/getsops/sops/v3/stores/ini"
	"github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/stores/yaml"
	"github.com/urfave/cli"
)

// ExampleFileEmitter emits example files. This is used by the `sops` binary
// whenever a new file is created, in order to present the user with a non-empty file
type ExampleFileEmitter interface {
	EmitExample() []byte
}

// Store handles marshaling and unmarshaling from SOPS files
type Store interface {
	sops.Store
	ExampleFileEmitter
}

type storeConstructor = func(*config.StoresConfig) Store

func newBinaryStore(c *config.StoresConfig) Store {
	return json.NewBinaryStore(&c.JSONBinary)
}

func newDotenvStore(c *config.StoresConfig) Store {
	return dotenv.NewStore(&c.Dotenv)
}

func newIniStore(c *config.StoresConfig) Store {
	return ini.NewStore(&c.INI)
}

func newJsonStore(c *config.StoresConfig) Store {
	return json.NewStore(&c.JSON)
}

func newYamlStore(c *config.StoresConfig) Store {
	return yaml.NewStore(&c.YAML)
}

var storeConstructors = map[Format]storeConstructor{
	Binary: newBinaryStore,
	Dotenv: newDotenvStore,
	Ini:    newIniStore,
	Json:   newJsonStore,
	Yaml:   newYamlStore,
}

// DecryptTreeOpts are the options needed to decrypt a tree
type DecryptTreeOpts struct {
	// Tree is the tree to be decrypted
	Tree *sops.Tree
	// KeyServices are the key services to be used for decryption of the data key
	KeyServices []keyservice.KeyServiceClient
	// DecryptionOrder is the order in which available decryption methods are tried
	DecryptionOrder []string
	// IgnoreMac is whether or not to ignore the Message Authentication Code included in the SOPS tree
	IgnoreMac bool
	// Cipher is the cryptographic cipher to use to decrypt the values inside the tree
	Cipher sops.Cipher
}

// DecryptTree decrypts the tree passed in through the DecryptTreeOpts and additionally returns the decrypted data key
func DecryptTree(opts DecryptTreeOpts) (dataKey []byte, err error) {
	dataKey, err = opts.Tree.Metadata.GetDataKeyWithKeyServices(opts.KeyServices, opts.DecryptionOrder)
	if err != nil {
		return nil, NewExitError(err, codes.CouldNotRetrieveKey)
	}
	computedMac, err := opts.Tree.Decrypt(dataKey, opts.Cipher)
	if err != nil {
		return nil, NewExitError(fmt.Sprintf("Error decrypting tree: %s", err), codes.ErrorDecryptingTree)
	}
	fileMac, err := opts.Cipher.Decrypt(opts.Tree.Metadata.MessageAuthenticationCode, dataKey, opts.Tree.Metadata.LastModified.Format(time.RFC3339))
	if !opts.IgnoreMac {
		if err != nil {
			return nil, NewExitError(fmt.Sprintf("Cannot decrypt MAC: %s", err), codes.MacMismatch)
		}
		if fileMac != computedMac {
			// If the file has an empty MAC, display "no MAC" instead of not displaying anything
			if fileMac == "" {
				fileMac = "no MAC"
			}
			return nil, NewExitError(fmt.Sprintf("MAC mismatch. File has %s, computed %s", fileMac, computedMac), codes.MacMismatch)
		}
	}
	return dataKey, nil
}

// EncryptTreeOpts are the options needed to encrypt a tree
type EncryptTreeOpts struct {
	// Tree is the tree to be encrypted
	Tree *sops.Tree
	// Cipher is the cryptographic cipher to use to encrypt the values inside the tree
	Cipher sops.Cipher
	// DataKey is the key the cipher should use to encrypt the values inside the tree
	DataKey []byte
}

// EncryptTree encrypts the tree passed in through the EncryptTreeOpts
func EncryptTree(opts EncryptTreeOpts) error {
	unencryptedMac, err := opts.Tree.Encrypt(opts.DataKey, opts.Cipher)
	if err != nil {
		return NewExitError(fmt.Sprintf("Error encrypting tree: %s", err), codes.ErrorEncryptingTree)
	}
	opts.Tree.Metadata.LastModified = time.Now().UTC()
	opts.Tree.Metadata.MessageAuthenticationCode, err = opts.Cipher.Encrypt(unencryptedMac, opts.DataKey, opts.Tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return NewExitError(fmt.Sprintf("Could not encrypt MAC: %s", err), codes.ErrorEncryptingMac)
	}
	return nil
}

// LoadEncryptedFile loads an encrypted SOPS file, returning a SOPS tree
func LoadEncryptedFile(loader sops.EncryptedFileLoader, inputPath string) (*sops.Tree, error) {
	fileBytes, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, NewExitError(fmt.Sprintf("Error reading file: %s", err), codes.CouldNotReadInputFile)
	}
	path, err := filepath.Abs(inputPath)
	if err != nil {
		return nil, err
	}
	tree, err := loader.LoadEncryptedFile(fileBytes)
	tree.FilePath = path
	return &tree, err
}

// NewExitError returns a cli.ExitError given an error (wrapped in a generic interface{})
// and an exit code to represent the failure
func NewExitError(i interface{}, exitCode int) *cli.ExitError {
	if userErr, ok := i.(sops.UserError); ok {
		return NewExitError(userErr.UserError(), exitCode)
	}
	return cli.NewExitError(i, exitCode)
}

// StoreForFormat returns the correct format-specific implementation
// of the Store interface given the format.
func StoreForFormat(format Format, c *config.StoresConfig) Store {
	storeConst, found := storeConstructors[format]
	if !found {
		storeConst = storeConstructors[Binary] // default
	}
	return storeConst(c)
}

// DefaultStoreForPath returns the correct format-specific implementation
// of the Store interface given the path to a file
func DefaultStoreForPath(c *config.StoresConfig, path string) Store {
	format := FormatForPath(path)
	return StoreForFormat(format, c)
}

// DefaultStoreForPathOrFormat returns the correct format-specific implementation
// of the Store interface given the formatString if specified, or the path to a file.
// This is to support the cli, where both are provided.
func DefaultStoreForPathOrFormat(c *config.StoresConfig, path string, format string) Store {
	formatFmt := FormatForPathOrString(path, format)
	return StoreForFormat(formatFmt, c)
}

// GenericDecryptOpts represents decryption options and config
type GenericDecryptOpts struct {
	Cipher          sops.Cipher
	InputStore      sops.Store
	InputPath       string
	IgnoreMAC       bool
	KeyServices     []keyservice.KeyServiceClient
	DecryptionOrder []string
}

// LoadEncryptedFileWithBugFixes is a wrapper around LoadEncryptedFile which includes
// check for the issue described in https://github.com/mozilla/sops/pull/435
func LoadEncryptedFileWithBugFixes(opts GenericDecryptOpts) (*sops.Tree, error) {
	tree, err := LoadEncryptedFile(opts.InputStore, opts.InputPath)
	if err != nil {
		return nil, err
	}

	return tree, nil
}

// Diff represents a key diff
type Diff struct {
	Common  []keys.MasterKey
	Added   []keys.MasterKey
	Removed []keys.MasterKey
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// DiffKeyGroups returns the list of diffs found in two sops.keyGroup slices
func DiffKeyGroups(ours, theirs []sops.KeyGroup) []Diff {
	var diffs []Diff
	for i := 0; i < max(len(ours), len(theirs)); i++ {
		var diff Diff
		var ourGroup, theirGroup sops.KeyGroup
		if len(ours) > i {
			ourGroup = ours[i]
		}
		if len(theirs) > i {
			theirGroup = theirs[i]
		}
		ourKeys := make(map[string]struct{})
		theirKeys := make(map[string]struct{})
		for _, key := range ourGroup {
			ourKeys[key.ToString()] = struct{}{}
		}
		for _, key := range theirGroup {
			if _, ok := ourKeys[key.ToString()]; ok {
				diff.Common = append(diff.Common, key)
			} else {
				diff.Added = append(diff.Added, key)
			}
			theirKeys[key.ToString()] = struct{}{}
		}
		for _, key := range ourGroup {
			if _, ok := theirKeys[key.ToString()]; !ok {
				diff.Removed = append(diff.Removed, key)
			}
		}
		diffs = append(diffs, diff)
	}
	return diffs
}

// PrettyPrintDiffs prints a slice of Diff objects to stdout
func PrettyPrintDiffs(diffs []Diff) {
	for i, diff := range diffs {
		color.New(color.Underline).Printf("Group %d\n", i+1)
		for _, c := range diff.Common {
			fmt.Printf("    %s\n", c.ToString())
		}
		for _, c := range diff.Added {
			color.New(color.FgGreen).Printf("+++ %s\n", c.ToString())
		}
		for _, c := range diff.Removed {
			color.New(color.FgRed).Printf("--- %s\n", c.ToString())
		}
	}
}

// PrettyPrintShamirDiff prints changes in shamir_threshold to stdout
func PrettyPrintShamirDiff(oldValue, newValue int) {
	if oldValue > 0 && oldValue == newValue {
		fmt.Printf("shamir_threshold: %d\n", newValue)
	} else {
		if newValue > 0 {
			color.New(color.FgGreen).Printf("+++ shamir_threshold: %d\n", newValue)
		}
		if oldValue > 0 {
			color.New(color.FgRed).Printf("--- shamir_threshold: %d\n", oldValue)
		}
	}
}
