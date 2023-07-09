package config


import (
    "bufio"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "strings"
)

type ConfigSection int

const (
	INTERFACE_SECTION ConfigSection = iota
	PEER_SECTION
	NONE
)

// This is probably not a comprehensive list of all valid keys, but its sufficient for most cases
type ConfigurationKeys []string

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

func (s ConfigSection) IsElementValid(key string) bool {
	if s == INTERFACE_SECTION {
		return VALID_INTERFACE_KEYS.has(key)
	} else if s == PEER_SECTION {
		return VALID_PEER_KEYS.has(key)
	} else {
		return false
	}
}

func (s ConfigSection) String() string {
	if s == INTERFACE_SECTION {
		return "[Interface]"
	} else if s == PEER_SECTION {
		return "[Peer]"
	} else {
		return "None"
	}
}

func parseConfig(config io.Reader) (iface_addresses, dns_addresses []netip.Addr, ipcConfig string, err error) {
	var private_key_set, public_key_set, endpoint_set, allowed_ip_set bool
	var interface_count, peer_count int
	var current_section ConfigSection = NONE

	var ipcConfigBuilder strings.Builder

	lineScanner := bufio.NewScanner(config)

	for lineScanner.Scan() {
		line := strings.TrimSpace(lineScanner.Text())
		if line == "" || line[0] == '#' { // skip empty lines and comments
			continue
		}

		if line == "[Interface]" {
			log.Debug("Found [Interface] section")
			interface_count++
			if interface_count > 1 {
				return nil, nil, "", errors.New("Only one [Interface] section is supported at the moment")
			}
			current_section = INTERFACE_SECTION
			continue
		}

		if line == "[Peer]" {
			log.Debug("Found [Peer] section")
			peer_count++
			if peer_count > 1 {
				return nil, nil, "", errors.New("Only one [Peer] section is supported at the moment")
			}
			current_section = PEER_SECTION
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Errorf("Invalid line in config: %s", lineScanner.Text())
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if !current_section.IsElementValid(key) {
			return nil, nil, "", fmt.Errorf("Invalid key %s in section %s", key, current_section.String())
		}

		switch key {
		case "PrivateKey":
			private_key_base64 := value

			private_key_bytes, err := base64.StdEncoding.DecodeString(private_key_base64)
			if err != nil {
				return nil, nil, "", fmt.Errorf("Error decoding private key: %s", err)
			}
			private_key_hex := hex.EncodeToString(private_key_bytes)

			ipcConfigBuilder.WriteString(fmt.Sprintf("private_key=%s\n", private_key_hex))
			private_key_set = true
		case "Address":
			// split by comma
			addresses := strings.Split(value, ",")
			if len(addresses) == 0 {
				return nil, nil, "", fmt.Errorf("No addresses found in Address field")
			}
			for _, address := range addresses {
				iface_addresses = append(iface_addresses, netip.MustParsePrefix(address).Addr())
			}
		case "DNS":
			// split by comma
			addresses := strings.Split(value, ",")
			if len(addresses) == 0 {
				return nil, nil, "", fmt.Errorf("No addresses found in DNS field")
			}
			for _, address := range addresses {
				dns_addresses = append(dns_addresses, netip.MustParseAddr(address))
			}
		case "PublicKey":
			public_key_base64 := value

			public_key_bytes, err := base64.StdEncoding.DecodeString(public_key_base64)
			if err != nil {
				return nil, nil, "", fmt.Errorf("Error decoding public key: %s", err)
			}

			public_key_hex := hex.EncodeToString(public_key_bytes)

			ipcConfigBuilder.WriteString(fmt.Sprintf("public_key=%s\n", public_key_hex))
			public_key_set = true
		case "AllowedIPs":
			// split by comma
			allowed_ips := strings.Split(value, ",")
			if len(allowed_ips) == 0 {
				return nil, nil, "", fmt.Errorf("No allowed IPs found in AllowedIPs field")
			}

			for _, allowed_ip := range allowed_ips {
				ipcConfigBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowed_ip))
				allowed_ip_set = true
			}
		case "Endpoint":
			ipcConfigBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", value))
			endpoint_set = true
		}

	}

	minimal_config_set := private_key_set && public_key_set && endpoint_set && allowed_ip_set && len(dns_addresses) > 0 && len(iface_addresses) > 0
	if !minimal_config_set {
		return nil, nil, "", fmt.Errorf("Configuration provided is not sufficient.")
	}

	return iface_addresses, dns_addresses, ipcConfigBuilder.String(), nil
}
