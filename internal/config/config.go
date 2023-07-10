package config

// Enum for the different sections in the config file, this is later when parsing a config file to determine the state
type ConfigSection int

const (
	SECTION_INTERFACE ConfigSection = iota
	SECTION_PEER
	SECTION_NONE
)

// Helper type to check if a key is valid for a given section
type ConfigurationKeys []string

func (s ConfigSection) IsElementValid(key string) bool {
	if s == SECTION_INTERFACE {
		return VALID_INTERFACE_KEYS.has(key)
	} else if s == SECTION_PEER {
		return VALID_PEER_KEYS.has(key)
	} else {
		return false
	}
}

func (s ConfigSection) String() string {
	if s == SECTION_INTERFACE {
		return "[Interface]"
	} else if s == SECTION_PEER {
		return "[Peer]"
	} else {
		return "None"
	}
}

// This is probably not a comprehensive list of all valid keys, but its sufficient for most cases
var VALID_INTERFACE_KEYS = ConfigurationKeys{"PrivateKey", "Address", "DNS", "ListenPort", "MTU", "SaveConfig", "PreUp", "PostUp", "PreDown", "PostDown", "Table", "FwMark"}
var VALID_PEER_KEYS = ConfigurationKeys{"PublicKey", "AllowedIPs", "Endpoint", "PersistentKeepalive", "PresharedKey"}

func (keys ConfigurationKeys) has(key string) bool {
	for _, s := range keys {
		if s == key {
			return true
		}
	}
	return false
}

