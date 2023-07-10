package wiredialer

import (
	"strings"
	"testing"
)

const VALID_CONFIG = `
[Interface]
Address = 4.3.2.1/32,3.2.1.0/16
PrivateKey = QvKsOZ9oQvBs5n79sOXWh4QnxLrIh5Ii34H3w/1mfGQ=
DNS = 1.1.1.1

[Peer]
PublicKey = QvKsOZ9oQvBs5n79sOXWh4QnxLrIh5Ii34H3w/1mfGQ=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 1.2.3.4:1234
`

func TestNewFromConfig(t *testing.T) {
	reader := strings.NewReader(VALID_CONFIG)
	_, err := NewDialerFromConfiguration(reader)
	if err != nil {
		t.Error(err)
	}
}
