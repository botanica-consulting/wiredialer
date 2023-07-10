package config

import (
    "testing"
    "strings"
)

const VALID_SAMPLE string = `
[Interface]
Address = 4.3.2.1/32,3.2.1.0/16
PrivateKey = YmxhaGJsYWhibGFoYmxhaGJsYWgK
DNS = 1.1.1.1

[Peer]
PublicKey = YmxhaGJsYWhibGFoYmxhaGJsYWgK
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 1.2.3.4:1234
`

func TestValidConfig(t *testing.T) {
    reader := strings.NewReader(VALID_SAMPLE)
    ifaceAddresses, dnsAddresses, mtu, ipcConfig, err := ParseConfig(reader)
    if err != nil {
        t.Errorf("Valid config should not return an error")
    }

    if len(ifaceAddresses) != 2 {
        t.Errorf("Interface should have 2 addresses")
    }

    if ifaceAddresses[0].String() != "4.3.2.1" {
        t.Errorf("%s is not expected address", ifaceAddresses[0].String())
    }

    if ifaceAddresses[1].String() != "3.2.1.0" {
        t.Errorf("%s is not expected address", ifaceAddresses[1].String())
    }

    if len(dnsAddresses) != 1 {
        t.Errorf("Interface should have 1 DNS address")
    }

    if dnsAddresses[0].String() != "1.1.1.1" {
        t.Errorf("%s is not expected address", dnsAddresses[0].String())
    }

    if mtu != DEFAULT_MTU {
        t.Errorf("MTU should be 1420")
    }

    const expectedIpcConfig string = `
    allowed_ip=0.0.0.0/0
    allowed_ip=::/0
    endpoint=1.2.3.4:1234
    private_key=626c6168626c6168626c6168626c6168626c61680a
    public_key=626c6168626c6168626c6168626c6168626c61680a
    `
    lineSplit := strings.Split(ipcConfig, "\n")
    if len(lineSplit) != 6 {
        t.Errorf("IPC config should have 6 lines")
    }
    // Compare line by line unordered
    for _, line := range lineSplit {
        if !strings.Contains(expectedIpcConfig, line) {
            t.Errorf("%s is not expected IPC config", line)
        }
    }
}

const INCOMPLETE_SAMPLE string = `
[Interface]
Address = 4.3.2.1/32,3.2.1.0/16
DNS = 1.1.1.1

[Peer]
PublicKey = YmxhaGJsYWhibGFoYmxhaGJsYWgK
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 1.2.3.4:1234
`

func TestIncompleteConfig(t *testing.T) {
    reader := strings.NewReader(INCOMPLETE_SAMPLE)
    _, _, _, _, err := ParseConfig(reader)
    if err == nil {
        t.Errorf("Incomplete config should return an error")
    }
}

const BAD_SECTION_SAMPLE string = `
[poor]
Address = 4.3.2.1/32,3.2.1.0/16
PrivateKey = YmxhaGJsYWhibGFoYmxhaGJsYWgK

[Peer]
PublicKey = YmxhaGJsYWhibGFoYmxhaGJsYWgK
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 1.2.3.4:1234
`

func TestBadSectionConfig(t *testing.T) {
    reader := strings.NewReader(BAD_SECTION_SAMPLE)
    _, _, _, _, err := ParseConfig(reader)
    if err == nil {
        t.Errorf("Bad section config should return an error")
    }
}

const BAD_KEY_SAMPLE string = `
[Interface]
Baddress = 4.3.2.1/32,3.2.1.0/16
PrivateKey = YmxhaGJsYWhibGFoYmxhaGJsYWgK

[Peer]
PublicKey = YmxhaGJsYWhibGFoYmxhaGJsYWgK
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 1.2.3.4:1234
`

func TestBadKeyConfig(t *testing.T) {
    reader := strings.NewReader(BAD_KEY_SAMPLE)
    _, _, _, _, err := ParseConfig(reader)
    if err == nil {
        t.Errorf("Bad key config should return an error")
    }
}

const BAD_IP_SAMPLE string = `
[Interface]
Address = 4.3.2.1/32,3.2.1/16

[Peer]
PublicKey = YmxhaGJsYWhibGFoYmxhaGJsYWgK
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 1.2.3.4:1234
`

func TestBadIPConfig(t *testing.T) {
    reader := strings.NewReader(BAD_IP_SAMPLE)
    _, _, _, _, err := ParseConfig(reader)
    if err == nil {
        t.Errorf("Bad IP config should return an error")
    }
}

