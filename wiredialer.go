package wiredialer

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"os"

	"net"
	"net/http"

	"context"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/botanica-consulting/wiredialer/internal/config"
)

type WireDialer struct {
	tun    tun.Device
	tnet   *netstack.Net
	device *device.Device
}

func (d *WireDialer) Dial(network, address string) (net.Conn, error) {
	return d.tnet.Dial(network, address)
}

func (d *WireDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tnet.DialContext(ctx, network, address)
}

func NewDialerFromFile(path string) (*WireDialer, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return NewDialerFromConfiguration(file)
}

func NewDialerFromConfiguration(config_reader io.Reader) (*WireDialer, error) {
	iface_addresses, dns_addresses, ipcConfig, err := config.ParseConfig(config_reader)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(
		iface_addresses,
		dns_addresses,
		1420)
	if err != nil {
		log.Panic(err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	err = dev.IpcSet(ipcConfig)
	err = dev.Up()
	if err != nil {
		log.Panic(err)
	}

	return &WireDialer{
		tun:    tun,
		tnet:   tnet,
		device: dev,
	}, nil
}

