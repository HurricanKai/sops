/*
Package config provides a way to find and load SOPS configuration files
*/
package config //import "github.com/getsops/sops/v3/config"

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/logging"
	"github.com/getsops/sops/v3/pgp"
	"github.com/getsops/sops/v3/publish"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("CONFIG")
}

type fileSystem interface {
	Stat(name string) (os.FileInfo, error)
}

type osFS struct {
	stat func(string) (os.FileInfo, error)
}

func (fs osFS) Stat(name string) (os.FileInfo, error) {
	return fs.stat(name)
}

var fs fileSystem = osFS{stat: os.Stat}

const (
	maxDepth       = 100
	configFileName = ".sops.yaml"
)

// FindConfigFile looks for a sops config file in the current working directory and on parent directories, up to the limit defined by the maxDepth constant.
func FindConfigFile(start string) (string, error) {
	filepath := path.Dir(start)
	for i := 0; i < maxDepth; i++ {
		_, err := fs.Stat(path.Join(filepath, configFileName))
		if err != nil {
			filepath = path.Join(filepath, "..")
		} else {
			return path.Join(filepath, configFileName), nil
		}
	}
	return "", fmt.Errorf("Config file not found")
}

type DotenvStoreConfig struct{}

type INIStoreConfig struct{}

type JSONStoreConfig struct {
	Indent int `yaml:"indent"`
}

type JSONBinaryStoreConfig struct {
	Indent int `yaml:"indent"`
}

type YAMLStoreConfig struct {
	Indent int `yaml:"indent"`
}

type StoresConfig struct {
	Dotenv     DotenvStoreConfig     `yaml:"dotenv"`
	INI        INIStoreConfig        `yaml:"ini"`
	JSONBinary JSONBinaryStoreConfig `yaml:"json_binary"`
	JSON       JSONStoreConfig       `yaml:"json"`
	YAML       YAMLStoreConfig       `yaml:"yaml"`
}

type configFile struct {
	CreationRules    []creationRule    `yaml:"creation_rules"`
	DestinationRules []destinationRule `yaml:"destination_rules"`
	Stores           StoresConfig      `yaml:"stores"`
}

type keyGroup struct {
	Merge   []keyGroup
	Age     []string     `yaml:"age"`
	PGP     []string
}

type destinationRule struct {
	PathRegex        string       `yaml:"path_regex"`
	RecreationRule   creationRule `yaml:"recreation_rule,omitempty"`
	OmitExtensions   bool         `yaml:"omit_extensions"`
}

type creationRule struct {
	PathRegex               string `yaml:"path_regex"`
	Age                     string `yaml:"age"`
	PGP                     string
	KeyGroups               []keyGroup `yaml:"key_groups"`
	ShamirThreshold         int        `yaml:"shamir_threshold"`
	UnencryptedSuffix       string     `yaml:"unencrypted_suffix"`
	EncryptedSuffix         string     `yaml:"encrypted_suffix"`
	UnencryptedRegex        string     `yaml:"unencrypted_regex"`
	EncryptedRegex          string     `yaml:"encrypted_regex"`
	UnencryptedCommentRegex string     `yaml:"unencrypted_comment_regex"`
	EncryptedCommentRegex   string     `yaml:"encrypted_comment_regex"`
	MACOnlyEncrypted        bool       `yaml:"mac_only_encrypted"`
}

func NewStoresConfig() *StoresConfig {
	storesConfig := &StoresConfig{}
	storesConfig.JSON.Indent = -1
	storesConfig.JSONBinary.Indent = -1
	return storesConfig
}

// Load loads a sops config file into a temporary struct
func (f *configFile) load(bytes []byte) error {
	err := yaml.Unmarshal(bytes, f)
	if err != nil {
		return fmt.Errorf("Could not unmarshal config file: %s", err)
	}
	return nil
}

// Config is the configuration for a given SOPS file
type Config struct {
	KeyGroups               []sops.KeyGroup
	ShamirThreshold         int
	UnencryptedSuffix       string
	EncryptedSuffix         string
	UnencryptedRegex        string
	EncryptedRegex          string
	UnencryptedCommentRegex string
	EncryptedCommentRegex   string
	MACOnlyEncrypted        bool
	Destination             publish.Destination
	OmitExtensions          bool
}

func deduplicateKeygroup(group sops.KeyGroup) sops.KeyGroup {
	var deduplicatedKeygroup sops.KeyGroup

	unique := make(map[string]bool)
	for _, v := range group {
		key := fmt.Sprintf("%T/%v", v, v.ToString())
		if _, ok := unique[key]; ok {
			// key already contained, therefore not unique
			continue
		}

		deduplicatedKeygroup = append(deduplicatedKeygroup, v)
		unique[key] = true
	}

	return deduplicatedKeygroup
}

func extractMasterKeys(group keyGroup) (sops.KeyGroup, error) {
	var keyGroup sops.KeyGroup
	for _, k := range group.Merge {
		subKeyGroup, err := extractMasterKeys(k)
		if err != nil {
			return nil, err
		}
		keyGroup = append(keyGroup, subKeyGroup...)
	}

	for _, k := range group.Age {
		keys, err := age.MasterKeysFromRecipients(k)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			keyGroup = append(keyGroup, key)
		}
	}
	for _, k := range group.PGP {
		keyGroup = append(keyGroup, pgp.NewMasterKeyFromFingerprint(k))
	}
	return deduplicateKeygroup(keyGroup), nil
}

func getKeyGroupsFromCreationRule(cRule *creationRule) ([]sops.KeyGroup, error) {
	var groups []sops.KeyGroup
	if len(cRule.KeyGroups) > 0 {
		for _, group := range cRule.KeyGroups {
			keyGroup, err := extractMasterKeys(group)
			if err != nil {
				return nil, err
			}
			groups = append(groups, keyGroup)
		}
	} else {
		var keyGroup sops.KeyGroup
		if cRule.Age != "" {
			ageKeys, err := age.MasterKeysFromRecipients(cRule.Age)
			if err != nil {
				return nil, err
			} else {
				for _, ak := range ageKeys {
					keyGroup = append(keyGroup, ak)
				}
			}
		}
		for _, k := range pgp.MasterKeysFromFingerprintString(cRule.PGP) {
			keyGroup = append(keyGroup, k)
		}
		groups = append(groups, keyGroup)
	}
	return groups, nil
}

func loadConfigFile(confPath string) (*configFile, error) {
	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %s", err)
	}
	conf := &configFile{}
	conf.Stores = *NewStoresConfig()
	err = conf.load(confBytes)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %s", err)
	}
	return conf, nil
}

func configFromRule(rule *creationRule) (*Config, error) {
	cryptRuleCount := 0
	if rule.UnencryptedSuffix != "" {
		cryptRuleCount++
	}
	if rule.EncryptedSuffix != "" {
		cryptRuleCount++
	}
	if rule.UnencryptedRegex != "" {
		cryptRuleCount++
	}
	if rule.EncryptedRegex != "" {
		cryptRuleCount++
	}
	if rule.UnencryptedCommentRegex != "" {
		cryptRuleCount++
	}
	if rule.EncryptedCommentRegex != "" {
		cryptRuleCount++
	}

	if cryptRuleCount > 1 {
		return nil, fmt.Errorf("error loading config: cannot use more than one of encrypted_suffix, unencrypted_suffix, encrypted_regex, unencrypted_regex, encrypted_comment_regex, or unencrypted_comment_regex for the same rule")
	}

	groups, err := getKeyGroupsFromCreationRule(rule)
	if err != nil {
		return nil, err
	}

	return &Config{
		KeyGroups:               groups,
		ShamirThreshold:         rule.ShamirThreshold,
		UnencryptedSuffix:       rule.UnencryptedSuffix,
		EncryptedSuffix:         rule.EncryptedSuffix,
		UnencryptedRegex:        rule.UnencryptedRegex,
		EncryptedRegex:          rule.EncryptedRegex,
		UnencryptedCommentRegex: rule.UnencryptedCommentRegex,
		EncryptedCommentRegex:   rule.EncryptedCommentRegex,
		MACOnlyEncrypted:        rule.MACOnlyEncrypted,
	}, nil
}

func parseDestinationRuleForFile(conf *configFile, filePath string) (*Config, error) {
	var rule *creationRule
	var dRule *destinationRule

	if len(conf.DestinationRules) > 0 {
		for _, r := range conf.DestinationRules {
			if r.PathRegex == "" {
				dRule = &r
				rule = &dRule.RecreationRule
				break
			}
			if r.PathRegex != "" {
				if match, _ := regexp.MatchString(r.PathRegex, filePath); match {
					dRule = &r
					rule = &dRule.RecreationRule
					break
				}
			}
		}
	}

	if dRule == nil {
		return nil, fmt.Errorf("error loading config: no matching destination found in config")
	}

	var dest publish.Destination

	config, err := configFromRule(rule)
	if err != nil {
		return nil, err
	}
	config.Destination = dest
	config.OmitExtensions = dRule.OmitExtensions

	return config, nil
}

func parseCreationRuleForFile(conf *configFile, confPath, filePath string) (*Config, error) {
	// If config file doesn't contain CreationRules (it's empty or only contains DestionationRules), assume it does not exist
	if conf.CreationRules == nil {
		return nil, nil
	}

	configDir, err := filepath.Abs(filepath.Dir(confPath))
	if err != nil {
		return nil, err
	}

	// compare file path relative to path of config file
	filePath = strings.TrimPrefix(filePath, configDir+string(filepath.Separator))

	var rule *creationRule

	for _, r := range conf.CreationRules {
		if r.PathRegex == "" {
			rule = &r
			break
		}
		reg, err := regexp.Compile(r.PathRegex)
		if err != nil {
			return nil, fmt.Errorf("can not compile regexp: %w", err)
		}
		if reg.MatchString(filePath) {
			rule = &r
			break
		}
	}

	if rule == nil {
		return nil, fmt.Errorf("error loading config: no matching creation rules found")
	}

	config, err := configFromRule(rule)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// LoadCreationRuleForFile load the configuration for a given SOPS file from the config file at confPath. A kmsEncryptionContext
// should be provided for configurations that do not contain key groups, as there's no way to specify context inside
// a SOPS config file outside of key groups.
func LoadCreationRuleForFile(confPath string, filePath string) (*Config, error) {
	conf, err := loadConfigFile(confPath)
	if err != nil {
		return nil, err
	}

	return parseCreationRuleForFile(conf, confPath, filePath)
}

// LoadDestinationRuleForFile works the same as LoadCreationRuleForFile, but gets the "creation_rule" from the matching destination_rule's
// "recreation_rule".
func LoadDestinationRuleForFile(confPath string, filePath string) (*Config, error) {
	conf, err := loadConfigFile(confPath)
	if err != nil {
		return nil, err
	}
	return parseDestinationRuleForFile(conf, filePath)
}

func LoadStoresConfig(confPath string) (*StoresConfig, error) {
	conf, err := loadConfigFile(confPath)
	if err != nil {
		return nil, err
	}
	return &conf.Stores, nil
}
