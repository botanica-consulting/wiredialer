package config

import (
    "bufio"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "strings"
    "strconv"
    "net/netip"
)

const DEFAULT_MTU = 1420 // MTU is not typically present in WireGuard config files, so a default is provided

// This function reads a configuration and returns the following parsed values:
// - ifaceAddresses: IP addresses with which to configure the local WireGuard interface
// - dnsAddresses: The DNS server to be used by the local WireGuard interface
// - mtu: MTU to be configured for the local WireGuard interface
// - ipcConfig: a string that can be used to configure the WireGuard UAPI via the IPC socket
// If the configuration file is incomplete, e.g. it is missing any fields mandatory for starting the tunnel, an error is returned
// At the moment, only one [Interface] and one [Peer] section is supported, as that is the most common use case
func ParseConfig(config io.Reader) (ifaceAddresses, dnsAddresses []netip.Addr, mtu int, ipcConfig string, err error) {
	var privateKeyPresent, publicKeyPresent, endpointPresent, allowedIpsPresent bool
	var interfaceCount, peerCount int
	var currentSection ConfigSection = SECTION_NONE

    mtu = DEFAULT_MTU

	var ipcConfigBuilder strings.Builder

	lineScanner := bufio.NewScanner(config)

	for lineScanner.Scan() {
		line := strings.TrimSpace(lineScanner.Text())
		if line == "" || line[0] == '#' { // skip empty lines and comments
			continue
		}

		if line == "[Interface]" {
			interfaceCount++
			if interfaceCount > 1 {
				return nil, nil, -1, "", errors.New("Only one [Interface] section is supported at the moment")
			}
			currentSection = SECTION_INTERFACE
			continue
		}

		if line == "[Peer]" {
			peerCount++
			if peerCount > 1 {
				return nil, nil, -1, "", errors.New("Only one [Peer] section is supported at the moment")
			}
			currentSection = SECTION_PEER
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
            return nil, nil, -1, "", fmt.Errorf("Invalid line in config: %s", lineScanner.Text())
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if !currentSection.IsElementValid(key) {
			return nil, nil, -1, "", fmt.Errorf("Invalid key %s in section %s", key, currentSection.String())
		}

		switch key {
		case "PrivateKey":
			privateKeyBase64 := value

			privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
			if err != nil {
				return nil, nil, -1, "", fmt.Errorf("Error decoding private key: %s", err)
			}
			privateKeyHex := hex.EncodeToString(privateKeyBytes)

			ipcConfigBuilder.WriteString(fmt.Sprintf("private_key=%s\n", privateKeyHex))
			privateKeyPresent = true
		case "Address":
			// split by comma
			addresses := strings.Split(value, ",")
			if len(addresses) == 0 {
				return nil, nil, -1, "", fmt.Errorf("No addresses found in Address field")
			}
			for _, address := range addresses {
                parsedAddress, err := netip.ParsePrefix(address)
                if err != nil {
                    return nil, nil, -1, "", fmt.Errorf("Error parsing address: %s", err)
                }
				ifaceAddresses = append(ifaceAddresses, parsedAddress.Addr())
			}
		case "MTU":
            mtu, err = strconv.Atoi(value)
            if err != nil {
                return nil, nil, -1, "", fmt.Errorf("Error parsing MTU: %s", err)
            }
		case "DNS":
			// split by comma
			addresses := strings.Split(value, ",")
			if len(addresses) == 0 {
				return nil, nil, -1, "", fmt.Errorf("No addresses found in DNS field")
			}
			for _, address := range addresses {
                parsedAddress, err := netip.ParseAddr(address)
                if err != nil {
                    return nil, nil, -1, "", fmt.Errorf("Error parsing address: %s", err)
                }
				dnsAddresses = append(dnsAddresses, parsedAddress)
			}
		case "PublicKey":
			publicKeyBase64 := value

			publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
			if err != nil {
				return nil, nil, -1, "", fmt.Errorf("Error decoding public key: %s", err)
			}

			publicKeyHex := hex.EncodeToString(publicKeyBytes)

			ipcConfigBuilder.WriteString(fmt.Sprintf("public_key=%s\n", publicKeyHex))
			publicKeyPresent = true
		case "AllowedIPs":
			// split by comma
			allowedIps := strings.Split(value, ",")
			if len(allowedIps) == 0 {
				return nil, nil, -1, "", fmt.Errorf("No allowed IPs found in AllowedIPs field")
			}

			for _, allowedIp := range allowedIps {
				ipcConfigBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIp))
				allowedIpsPresent = true
			}
		case "Endpoint":
			ipcConfigBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", value))
			endpointPresent = true
		}

	}

    // Determine if we have enough information to start the tunnel
	minimalConfigPresent := privateKeyPresent && publicKeyPresent && endpointPresent && allowedIpsPresent && len(dnsAddresses) > 0 && len(ifaceAddresses) > 0
	if !minimalConfigPresent {
		return nil, nil, -1, "", fmt.Errorf("Configuration provided is not sufficient.")
	}

	return ifaceAddresses, dnsAddresses, mtu, ipcConfigBuilder.String(), nil
}
