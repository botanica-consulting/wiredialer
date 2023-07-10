package config

import (
    "testing"
)

func TestSectionKeys(t *testing.T) {
    var interfaceSection ConfigSection = SECTION_INTERFACE
    var peerSection ConfigSection = SECTION_PEER

    for _, k := range VALID_INTERFACE_KEYS {
        if !interfaceSection.IsElementValid(k) {
            t.Errorf("Key %s should be valid for SECTION_INTERFACE", k)
        }

        if peerSection.IsElementValid(k) {
            t.Errorf("Key %s should not be valid for SECTION_PEER", k)
        }
    }

    for _, k := range VALID_PEER_KEYS {
        if !peerSection.IsElementValid(k) {
            t.Errorf("Key %s should be valid for SECTION_PEER", k)
        }

        if interfaceSection.IsElementValid(k) {
            t.Errorf("Key %s should not be valid for SECTION_INTERFACE", k)
        }
    }
}

