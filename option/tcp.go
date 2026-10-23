package option

import (
	"math"
	"net/netip"
	"strconv"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// maxTCPSocketOptionValue is the largest value the platform socket option
// interfaces accept for an integer option. Values above it are rejected
// instead of being truncated by the kernel ABI.
const maxTCPSocketOptionValue = math.MaxInt32

// maxTCPListenBindings is the source limit of tpws (params.h:31, MAX_BINDS).
const maxTCPListenBindings = 32

// TCPSocketOptions is the reusable typed socket-option object shared by
// TCP listen sockets and TCP dialer sockets. Every leaf is optional and
// absence (or zero) means the previous system behavior: no setsockopt call is
// made. It is not a generic setsockopt bag: only the implemented controls are
// exposed here.
type TCPSocketOptions struct {
	ReceiveBufferSize *uint32             `json:"receive_buffer_size,omitempty"`
	SendBufferSize    *uint32             `json:"send_buffer_size,omitempty"`
	UserTimeout       *badoption.Duration `json:"user_timeout,omitempty"`
}

// TCPOptions is the validated, platform-adjusted form of TCPSocketOptions.
// Zero means "no call". ReceiveBufferSize/SendBufferSize already contain the
// value written to the socket (Linux passes requested/2, other targets pass
// the requested bytes directly). UserTimeoutMillis is the checked millisecond
// value of TCP_USER_TIMEOUT.
type TCPOptions struct {
	ReceiveBufferSize int
	SendBufferSize    int
	UserTimeoutMillis int
}

func (o TCPOptions) Empty() bool {
	return o.ReceiveBufferSize == 0 && o.SendBufferSize == 0 && o.UserTimeoutMillis == 0
}

// Build validates the leaves and returns the platform-adjusted socket values.
func (o TCPSocketOptions) Build() (TCPOptions, error) {
	return o.BuildForPlatform(C.IsLinux)
}

// BuildForPlatform is Build with an explicit platform fact. It exists so the
// Linux halving rule and the Windows source-inapplicability rule are testable
// from one host.
func (o TCPSocketOptions) BuildForPlatform(linux bool) (TCPOptions, error) {
	var result TCPOptions
	if o.ReceiveBufferSize != nil {
		if *o.ReceiveBufferSize > maxTCPSocketOptionValue {
			return TCPOptions{}, E.New("tcp_socket_options.receive_buffer_size: value ", *o.ReceiveBufferSize, " exceeds the signed socket option range")
		}
		result.ReceiveBufferSize = int(*o.ReceiveBufferSize)
		if linux {
			// tpws.c:1364-1390 passes the requested bytes divided by two to
			// SO_RCVBUF/SO_SNDBUF; zero after division makes no call.
			result.ReceiveBufferSize /= 2
		}
	}
	if o.SendBufferSize != nil {
		if *o.SendBufferSize > maxTCPSocketOptionValue {
			return TCPOptions{}, E.New("tcp_socket_options.send_buffer_size: value ", *o.SendBufferSize, " exceeds the signed socket option range")
		}
		result.SendBufferSize = int(*o.SendBufferSize)
		if linux {
			result.SendBufferSize /= 2
		}
	}
	if o.UserTimeout != nil {
		timeout := time.Duration(*o.UserTimeout)
		if timeout < 0 {
			return TCPOptions{}, E.New("tcp_socket_options.user_timeout: value must not be negative")
		}
		if timeout > 0 {
			if timeout%time.Millisecond != 0 {
				return TCPOptions{}, E.New("tcp_socket_options.user_timeout: value must be a whole number of milliseconds")
			}
			millis := timeout / time.Millisecond
			if millis > maxTCPSocketOptionValue {
				return TCPOptions{}, E.New("tcp_socket_options.user_timeout: value overflows the millisecond socket option range")
			}
			if !linux {
				// TCP_USER_TIMEOUT bounds unacknowledged transmitted data. It
				// has no Winsock equivalent and is not emulated with read
				// deadlines or TCP_MAXRT; source-inapplicable is an explicit
				// configuration error, never a silent no-op.
				return TCPOptions{}, E.New("tcp_socket_options.user_timeout: TCP_USER_TIMEOUT is only implemented on Linux; it is not supported on this platform")
			}
			result.UserTimeoutMillis = int(millis)
		}
	}
	return result, nil
}

// TCPListenLinkLocal is the accepted `link_local` enum of a TCP listen
// binding. The empty value is the source default `unwanted`.
type TCPListenLinkLocal string

const (
	TCPListenLinkLocalUnwanted TCPListenLinkLocal = "unwanted"
	TCPListenLinkLocalNo       TCPListenLinkLocal = "no"
	TCPListenLinkLocalPrefer   TCPListenLinkLocal = "prefer"
	TCPListenLinkLocalForce    TCPListenLinkLocal = "force"
)

func (v TCPListenLinkLocal) Build() (TCPListenLinkLocal, error) {
	switch v {
	case "", TCPListenLinkLocalUnwanted:
		return TCPListenLinkLocalUnwanted, nil
	case TCPListenLinkLocalNo, TCPListenLinkLocalPrefer, TCPListenLinkLocalForce:
		return v, nil
	default:
		return "", E.New("unknown tcp_listen_bindings.link_local: ", string(v))
	}
}

func (v TCPListenLinkLocal) MarshalJSON() ([]byte, error) {
	built, err := v.Build()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(built))
}

func (v *TCPListenLinkLocal) UnmarshalJSON(content []byte) error {
	var value string
	err := json.Unmarshal(content, &value)
	if err != nil {
		return err
	}
	built, err := TCPListenLinkLocal(value).Build()
	if err != nil {
		return err
	}
	*v = built
	return nil
}

func (v TCPListenLinkLocal) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.StringEnum(
		string(TCPListenLinkLocalUnwanted),
		string(TCPListenLinkLocalNo),
		string(TCPListenLinkLocalPrefer),
		string(TCPListenLinkLocalForce),
	), nil
}

// TCPListenBindingList is the concrete list type of
// ListenOptions.tcp_listen_bindings. It is referenced through a pointer in
// ListenOptions because the listen options value must stay comparable for
// existing inbound option equality checks.
type TCPListenBindingList []TCPListenBinding

// TCPBindings returns the configured binding list, or nil when absent.
func (o ListenOptions) TCPBindings() TCPListenBindingList {
	if o.TCPListenBindings == nil {
		return nil
	}
	return *o.TCPListenBindings
}

// TCPMaxConnectionLimit returns the configured admission limit, or zero when
// absent.
func (o ListenOptions) TCPMaxConnectionLimit() int {
	if o.TCPMaxConnections == nil {
		return 0
	}
	return int(*o.TCPMaxConnections)
}

// TCPListenBinding is one entry of ListenOptions.tcp_listen_bindings. An
// explicit address and interface-address selection are alternative modes:
// an interface next to an explicit address only scopes its zone/wait
// condition and never permits choosing a different address.
type TCPListenBinding struct {
	Address         *badoption.Addr    `json:"address,omitempty"`
	Interface       string             `json:"interface,omitempty"`
	IPVersion       int                `json:"ip_version,omitempty" enum:"4,6"`
	LinkLocal       TCPListenLinkLocal `json:"link_local,omitempty"`
	WaitIfUp        badoption.Duration `json:"wait_ifup,omitempty"`
	WaitIP          badoption.Duration `json:"wait_ip,omitempty"`
	WaitIPLinkLocal badoption.Duration `json:"wait_ip_linklocal,omitempty"`
}

func addressIPVersion(address netip.Addr) int {
	if address.Is4() {
		return 4
	}
	return 6
}

func (b TCPListenBinding) address() netip.Addr {
	if b.Address == nil {
		return netip.Addr{}
	}
	return b.Address.Build(netip.Addr{})
}

func (b TCPListenBinding) validate(index int) error {
	prefix := E.New("tcp_listen_bindings[", index, "]: ")
	linkLocal, err := b.LinkLocal.Build()
	if err != nil {
		return E.Cause(err, prefix)
	}
	if b.WaitIfUp < 0 || b.WaitIP < 0 || b.WaitIPLinkLocal < 0 {
		return E.Cause(E.New("wait durations must not be negative"), prefix)
	}
	address := b.address()
	if b.IPVersion != 0 && b.IPVersion != 4 && b.IPVersion != 6 {
		return E.Cause(E.New("ip_version must be 4 or 6"), prefix)
	}
	if address.IsValid() {
		if b.IPVersion != 0 && b.IPVersion != addressIPVersion(address) {
			return E.Cause(E.New("ip_version ", b.IPVersion, " does not match address ", address), prefix)
		}
	} else {
		if b.IPVersion == 0 {
			return E.Cause(E.New("an interface-selected binding requires ip_version 4 or 6"), prefix)
		}
		if b.Interface == "" && !(b.IPVersion == 6 && (linkLocal == TCPListenLinkLocalPrefer || linkLocal == TCPListenLinkLocalForce)) {
			return E.Cause(E.New("an interface-selected binding requires interface, except IPv6 link_local prefer/force"), prefix)
		}
	}
	if b.WaitIfUp != 0 && b.Interface == "" {
		return E.Cause(E.New("wait_ifup requires interface"), prefix)
	}
	if b.WaitIPLinkLocal != 0 && !(b.IPVersion == 6 && (linkLocal == TCPListenLinkLocalUnwanted || linkLocal == TCPListenLinkLocalPrefer)) {
		return E.Cause(E.New("wait_ip_linklocal requires ip_version 6 and link_local unwanted or prefer"), prefix)
	}
	return nil
}

// ValidateTCPListenBindings applies the accepted schema rules, including the
// source limit of 32 bindings and exact duplicate entries.
func ValidateTCPListenBindings(bindings []TCPListenBinding) error {
	if len(bindings) > maxTCPListenBindings {
		return E.New("tcp_listen_bindings: at most ", maxTCPListenBindings, " entries are supported, got ", len(bindings))
	}
	seen := make(map[string]int, len(bindings))
	for index := range bindings {
		if err := bindings[index].validate(index); err != nil {
			return err
		}
		binding := bindings[index]
		key := binding.address().String() + "\x00" + binding.Interface + "\x00" +
			strconv.Itoa(binding.IPVersion) + "\x00" + string(binding.LinkLocal.BuildDefault())
		if previous, loaded := seen[key]; loaded {
			return E.New("tcp_listen_bindings: entry ", index, " duplicates entry ", previous)
		}
		seen[key] = index
	}
	return nil
}

// BuildDefault is the validation-free normalized enum used for duplicate
// detection already validated by validate().
func (v TCPListenLinkLocal) BuildDefault() TCPListenLinkLocal {
	built, err := v.Build()
	if err != nil {
		return TCPListenLinkLocalUnwanted
	}
	return built
}
