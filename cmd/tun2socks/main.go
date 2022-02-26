package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/wzshiming/tun"
	"github.com/wzshiming/tun/control"
	_ "github.com/wzshiming/tun/device/fd"
	_ "github.com/wzshiming/tun/device/tun"
)

var conf = tun.Config{}

var (
	mark          int
	interfaceName string
	route         string
)

func init() {
	flag.IntVar(&mark, "fwmark", 0, "Set firewall MARK (Linux only)")
	flag.IntVar(&conf.MTU, "mtu", 0, "Set device maximum transmission unit (MTU)")
	flag.StringVar(&conf.Device, "device", "", "Use this device")
	flag.StringVar(&conf.Name, "name", "", "Use this device name")
	flag.StringVar(&route, "route", "10.0.0.0/8", "Set the route")
	flag.StringVar(&interfaceName, "interface", "", "Use network INTERFACE (Linux/MacOS only)")
	flag.Parse()
}

func main() {
	logger := log.New(os.Stderr, "[tun] ", log.LstdFlags)

	controls := []control.ControlFunc{}

	if mark != 0 {
		controls = append(controls, control.ControlSocketMark(mark))
	}

	if interfaceName != "" {
		i, err := net.InterfaceByName(interfaceName)
		if err == nil {
			controls = append(controls, control.ControlBindToInterface(i))
		}
	}
	var dialer net.Dialer
	var listenConfig net.ListenConfig

	if len(controls) != 0 {
		ctr := control.Controls(controls...)
		dialer.Control = ctr
		listenConfig.Control = ctr
	}

	conf.Logger = logger
	conf.Dialer = WrapDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		logger.Println("Dial", network, address)
		return dialer.DialContext(ctx, network, "www.baidu.com:80")
		return dialer.DialContext(ctx, network, address)
	})
	conf.ListenPacket = &listenConfig

	t := tun.NewTun(conf)

	err := t.Start()
	if err != nil {
		logger.Printf("start: %v", err)
		os.Exit(1)
	}
	defer func() {
		err := t.Close()
		if err != nil {
			logger.Printf("close: %v", err)
		}
	}()

	err = t.SetRoute([]string{route})
	if err != nil {
		logger.Printf("SetRoute: %s", err)
		os.Exit(1)
	}

	logger.Println("Started")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

type WrapDialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (w WrapDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return w(ctx, network, address)
}
