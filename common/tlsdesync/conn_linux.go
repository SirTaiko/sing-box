package tlsdesync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/sing/common"
	"golang.org/x/sys/unix"
)

const Supported = true
const bypassMark = 0x40000000

type Conn struct {
	net.Conn
	options Options
	mu      sync.Mutex
	started bool
	closed  bool
	err     error
	engine  *engine
}

func NewConn(conn net.Conn, options Options) (net.Conn, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	tcp, ok := common.Cast[*net.TCPConn](conn)
	if !ok || tcp.LocalAddr().(*net.TCPAddr).IP.To4() == nil || tcp.RemoteAddr().(*net.TCPAddr).IP.To4() == nil {
		return nil, fmt.Errorf("tls_desync: experimental implementation requires a direct IPv4 TCP socket")
	}
	return &Conn{Conn: conn, options: options}, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if c.err != nil {
		c.mu.Unlock()
		return 0, c.err
	}
	if !c.started && len(b) > 0 {
		c.started = true
		if _, err := c.options.splitPoints(b); err != nil {
			c.err = err
			c.mu.Unlock()
			return 0, err
		}
		e, err := startEngine(c.Conn, c.options, b)
		if err != nil {
			c.err = err
			c.mu.Unlock()
			return 0, err
		}
		c.engine = e
	}
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *Conn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.engine != nil {
		err = errors.Join(err, c.engine.close())
		c.engine = nil
	}
	return err
}

type engine struct {
	queue    uint16
	nl       *netlink.Conn
	raw      int
	dst      *unix.SockaddrInet4
	nft      *nftables.Conn
	table    *nftables.Table
	options  Options
	tcp      *net.TCPConn
	done     chan struct{}
	stop     chan struct{}
	sequence *uint32
}

func startEngine(conn net.Conn, options Options, hello []byte) (_ *engine, err error) {
	if options.OverlapPattern != "" {
		f, openErr := os.Open(options.OverlapPattern)
		if openErr != nil {
			return nil, openErr
		}
		options.pattern, err = io.ReadAll(io.LimitReader(f, 16385))
		f.Close()
		if err != nil || len(options.pattern) == 0 || len(options.pattern) > 16384 {
			return nil, fmt.Errorf("tls_desync: overlap_pattern must contain 1..16384 bytes")
		}
	}
	tcp, _ := common.Cast[*net.TCPConn](conn)
	src, dst := tcp.LocalAddr().(*net.TCPAddr), tcp.RemoteAddr().(*net.TCPAddr)
	e := &engine{queue: uint16(src.Port), raw: -1, options: options, tcp: tcp, done: make(chan struct{}), stop: make(chan struct{})}
	// Each engine owns a distinct table and NFQUEUE. No shared firewall chain
	// is changed. Shutdown removes the table before closing the queue socket.
	defer func() {
		if err != nil {
			e.closeResources()
			if e.raw >= 0 {
				unix.Close(e.raw)
			}
		}
	}()
	var mss, mark int
	var device string
	rawConn, err := tcp.SyscallConn()
	if err != nil {
		return nil, err
	}
	var controlErr error
	err = rawConn.Control(func(fd uintptr) {
		info, infoErr := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if infoErr != nil {
			controlErr = infoErr
			return
		}
		mss = int(info.Snd_mss)
		mark, controlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		if controlErr == nil {
			device, controlErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		}
	})
	if err != nil || controlErr != nil {
		return nil, errors.Join(err, controlErr)
	}
	if len(hello) > mss {
		return nil, fmt.Errorf("tls_desync: ClientHello (%d) exceeds socket MSS (%d); reassembly not implemented", len(hello), mss)
	}
	// Preflight all packet transformations before installing a rule.
	template := make([]byte, 40+len(hello))
	template[0], template[9], template[32] = 0x45, 6, 5<<4
	binary.BigEndian.PutUint16(template[2:4], uint16(len(template)))
	copy(template[40:], hello)
	packets, err := options.packets(template)
	if err != nil {
		return nil, err
	}
	for _, packet := range packets {
		start, _ := packetPayload(packet)
		if len(packet)-start > mss {
			return nil, fmt.Errorf("tls_desync: generated payload exceeds MSS")
		}
	}
	e.raw, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("tls_desync: raw socket: %w", err)
	}
	if err = unix.SetsockoptInt(e.raw, unix.SOL_SOCKET, unix.SO_MARK, mark|bypassMark); err != nil {
		return nil, err
	}
	if device != "" {
		if err = unix.SetsockoptString(e.raw, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device); err != nil {
			return nil, err
		}
	}
	e.dst = &unix.SockaddrInet4{}
	copy(e.dst.Addr[:], dst.IP.To4())
	e.nl, err = netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	// nfqnl_msg_config_cmd: command=NFQNL_CFG_CMD_BIND, pf=AF_INET.
	if err = e.configure([]netlink.Attribute{{Type: 1, Data: []byte{1, 0, 0, unix.AF_INET}}}); err != nil {
		return nil, fmt.Errorf("tls_desync: bind NFQUEUE: %w", err)
	}
	if err = e.configure([]netlink.Attribute{{Type: 2, Data: []byte{0, 0, 0xff, 0xff, 2}}}); err != nil {
		return nil, fmt.Errorf("tls_desync: configure NFQUEUE: %w", err)
	}
	e.nft = &nftables.Conn{}
	e.table = e.nft.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: fmt.Sprintf("sb_dpi_%d_%d", os.Getpid(), src.Port)})
	chain := e.nft.AddChain(&nftables.Chain{Table: e.table, Name: "output", Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle})
	addresses := append(append([]byte(nil), src.IP.To4()...), dst.IP.To4()...)
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[:2], uint16(src.Port))
	binary.BigEndian.PutUint16(ports[2:], uint16(dst.Port))
	mask := make([]byte, 4)
	binary.NativeEndian.PutUint32(mask, bypassMark)
	e.nft.AddRule(&nftables.Rule{Table: e.table, Chain: chain, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 8},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addresses},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: make([]byte, 4)},
		&expr.Queue{Num: e.queue, Flag: expr.QueueFlagBypass},
	}})
	if err = e.nft.Flush(); err != nil {
		return nil, fmt.Errorf("tls_desync: install tuple-specific nftables rule: %w", err)
	}
	go e.loop()
	return e, nil
}

func (e *engine) message(typ uint16, attrs []netlink.Attribute, ack bool) (netlink.Message, error) {
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return netlink.Message{}, err
	}
	header := []byte{unix.AF_INET, 0, byte(e.queue >> 8), byte(e.queue)}
	flags := netlink.Request
	if ack {
		flags |= netlink.Acknowledge
	}
	return netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(3<<8 | typ), Flags: flags}, Data: append(header, data...)}, nil
}

func (e *engine) configure(attrs []netlink.Attribute) error {
	m, err := e.message(2, attrs, true)
	if err != nil {
		return err
	}
	_, err = e.nl.Execute(m)
	return err
}

func (e *engine) loop() {
	defer close(e.done)
	for {
		messages, err := e.nl.Receive()
		if err != nil {
			e.tcp.Close()
			return
		}
		for _, m := range messages {
			if uint16(m.Header.Type) != 3<<8 || len(m.Data) < 4 {
				continue
			}
			attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
			if err != nil {
				e.tcp.Close()
				return
			}
			var id, frame []byte
			for _, a := range attrs {
				switch a.Type & 0x3fff {
				case 1:
					if len(a.Data) >= 4 {
						id = a.Data[:4]
					}
				case 10:
					frame = a.Data
				}
			}
			if len(id) != 4 {
				e.tcp.Close()
				return
			}
			verdict := uint32(1) // NF_ACCEPT for ACKs and all later data.
			start, parseErr := packetPayload(frame)
			if parseErr == nil && len(frame)-start >= 6 && frame[start] == 22 && frame[start+5] == 1 {
				ip := int(frame[0]&15) * 4
				seq := binary.BigEndian.Uint32(frame[ip+4 : ip+8])
				if e.sequence == nil || *e.sequence == seq {
					e.sequence = &seq
					packets, transformErr := e.options.packets(frame)
					verdict = 0 // Replace the kernel packet, including retransmits.
					if transformErr == nil {
						for i, packet := range packets {
							select {
							case <-e.stop:
								return
							default:
							}
							if i > 0 && e.options.SegmentDelayMS > 0 {
								timer := time.NewTimer(time.Duration(e.options.SegmentDelayMS) * time.Millisecond)
								select {
								case <-timer.C:
								case <-e.stop:
									timer.Stop()
									return
								}
							}
							if transformErr = unix.Sendto(e.raw, packet, 0, e.dst); transformErr != nil {
								break
							}
						}
					}
					if transformErr != nil {
						e.tcp.Close()
					}
				}
			}
			v := make([]byte, 8)
			binary.BigEndian.PutUint32(v[:4], verdict)
			copy(v[4:], id)
			msg, _ := e.message(1, []netlink.Attribute{{Type: 2, Data: v}}, false)
			if _, err = e.nl.Send(msg); err != nil {
				e.tcp.Close()
				return
			}
		}
	}
}

func (e *engine) closeResources() error {
	var err error
	if e.table != nil {
		e.nft.DelTable(e.table)
		err = e.nft.Flush()
		e.table = nil
	}
	if e.nl != nil {
		err = errors.Join(err, e.nl.Close())
	}
	return err
}

func (e *engine) close() error {
	close(e.stop)
	err := e.closeResources()
	<-e.done
	if e.raw >= 0 {
		err = errors.Join(err, unix.Close(e.raw))
		e.raw = -1
	}
	return err
}
