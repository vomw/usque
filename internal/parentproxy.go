package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// ParentProxy is a SOCKS5/SOCKS5H parent transport. SOCKS5 resolves target
// hostnames locally; SOCKS5H gives the hostname to the proxy to resolve.
type ParentProxy struct { address, username, password string; remoteDNS bool }

func NewParentProxy(raw string) (*ParentProxy, error) {
	if raw == "" { return nil, nil }
	u, err := url.Parse(raw)
	if err != nil { return nil, fmt.Errorf("invalid parent_proxy: %w", err) }
	if u.Scheme != "socks5" && u.Scheme != "socks5h" { return nil, fmt.Errorf("parent_proxy must use socks5 or socks5h") }
	if u.Hostname() == "" || u.Port() == "" { return nil, fmt.Errorf("parent_proxy must include host and port") }
	if u.Path != "" && u.Path != "/" { return nil, fmt.Errorf("parent_proxy must not include a path") }
	p := &ParentProxy{address: u.Host, remoteDNS: u.Scheme == "socks5h"}
	if u.User != nil { p.username = u.User.Username(); p.password, _ = u.User.Password() }
	return p, nil
}

func (p *ParentProxy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if p == nil { return (&net.Dialer{}).DialContext(ctx, network, address) }
	if network != "tcp" && network != "tcp4" && network != "tcp6" { return nil, fmt.Errorf("SOCKS parent does not support %s connections", network) }
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil { return nil, fmt.Errorf("dial parent SOCKS proxy: %w", err) }
	if _, err := p.handshake(c, 1, address); err != nil { _ = c.Close(); return nil, err }
	return c, nil
}

// ListenPacket creates a SOCKS5 UDP ASSOCIATE connection. Closing the returned
// PacketConn also closes the TCP control connection as required by RFC 1928.
func (p *ParentProxy) ListenPacket(ctx context.Context, network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	if p == nil { return net.ListenUDP(network, laddr) }
	if network != "udp" && network != "udp4" && network != "udp6" { return nil, fmt.Errorf("unsupported UDP network %s", network) }
	control, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil { return nil, fmt.Errorf("dial parent SOCKS proxy: %w", err) }
	relay, err := p.handshake(control, 3, "0.0.0.0:0")
	if err != nil { _ = control.Close(); return nil, err }
	if relay.IP.IsUnspecified() { relay.IP = control.RemoteAddr().(*net.TCPAddr).IP }
	// DialUDP returns a connected UDP socket on every supported Go version,
	// including the older toolchains used by the release workflow.
	udp, err := net.DialUDP(network, laddr, relay)
	if err != nil { _ = control.Close(); return nil, err }
	return &socksUDPConn{UDPConn: udp, control: control}, nil
}

func (p *ParentProxy) handshake(c net.Conn, command byte, target string) (*net.UDPAddr, error) {
	methods := []byte{0}
	if p.username != "" || p.password != "" { methods = []byte{0, 2} }
	if _, err := c.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil { return nil, err }
	var selected [2]byte
	if _, err := io.ReadFull(c, selected[:]); err != nil { return nil, err }
	if selected[0] != 5 || selected[1] == 255 { return nil, fmt.Errorf("parent SOCKS proxy rejected authentication") }
	if selected[1] == 2 {
		if len(p.username) > 255 || len(p.password) > 255 { return nil, fmt.Errorf("parent SOCKS credentials are too long") }
		msg := append([]byte{1, byte(len(p.username))}, p.username...); msg = append(msg, byte(len(p.password))); msg = append(msg, p.password...)
		if _, err := c.Write(msg); err != nil { return nil, err }; if _, err := io.ReadFull(c, selected[:]); err != nil { return nil, err }; if selected[1] != 0 { return nil, fmt.Errorf("parent SOCKS authentication failed") }
	} else if selected[1] != 0 { return nil, fmt.Errorf("unsupported parent SOCKS authentication method %d", selected[1]) }
	addr, err := p.requestAddress(target); if err != nil { return nil, err }
	if _, err := c.Write(append([]byte{5, command, 0}, addr...)); err != nil { return nil, err }
	var head [4]byte; if _, err := io.ReadFull(c, head[:]); err != nil { return nil, err }
	if head[0] != 5 || head[1] != 0 { return nil, fmt.Errorf("parent SOCKS proxy request failed: %s", socksReplyError(head[1])) }
	if command != 3 { if err := discardSocksAddress(c, head[3]); err != nil { return nil, err }; return nil, nil }
	return socksReplyAddressBody(c, head[3])
}

func (p *ParentProxy) requestAddress(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target); if err != nil { return nil, err }
	port, err := strconv.ParseUint(portText, 10, 16); if err != nil { return nil, err }
	if !p.remoteDNS && net.ParseIP(host) == nil { ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host); if err != nil || len(ips) == 0 { return nil, fmt.Errorf("resolve %s: %w", host, err) }; host = ips[0].String() }
	var out []byte
	if ip := net.ParseIP(host); ip != nil { if ip4 := ip.To4(); ip4 != nil { out = append([]byte{1}, ip4...) } else { out = append([]byte{4}, ip.To16()...) } } else { if len(host) > 255 { return nil, fmt.Errorf("SOCKS hostname is too long") }; out = append([]byte{3, byte(len(host))}, host...) }
	var b [2]byte; binary.BigEndian.PutUint16(b[:], uint16(port)); return append(out, b[:]...), nil
}

func discardSocksAddress(r io.Reader, atyp byte) error { n := 0; switch atyp { case 1: n=4; case 4: n=16; case 3: var l [1]byte; if _,err:=io.ReadFull(r,l[:]);err!=nil{return err}; n=int(l[0]); default: return fmt.Errorf("invalid SOCKS address type %d", atyp) }; _,err:=io.CopyN(io.Discard,r,int64(n+2)); return err }
func socksReplyAddressBody(r io.Reader, atyp byte) (*net.UDPAddr, error) { var ip net.IP; switch atyp { case 1: ip=make(net.IP,4); if _,err:=io.ReadFull(r,ip);err!=nil{return nil,err}; case 4: ip=make(net.IP,16); if _,err:=io.ReadFull(r,ip);err!=nil{return nil,err}; case 3: var l [1]byte; if _,err:=io.ReadFull(r,l[:]);err!=nil{return nil,err}; host:=make([]byte,l[0]); if _,err:=io.ReadFull(r,host);err!=nil{return nil,err}; ips,err:=net.DefaultResolver.LookupIP(context.Background(),"ip",string(host)); if err!=nil || len(ips)==0{return nil,fmt.Errorf("resolve SOCKS UDP relay %q: %w",host,err)}; ip=ips[0]; default: return nil,fmt.Errorf("invalid SOCKS UDP relay address type") }; var b [2]byte; if _,err:=io.ReadFull(r,b[:]);err!=nil{return nil,err}; return &net.UDPAddr{IP:ip,Port:int(binary.BigEndian.Uint16(b[:]))},nil }
func socksReplyError(code byte) string { return map[byte]string{1:"general failure",2:"connection not allowed",3:"network unreachable",4:"host unreachable",5:"connection refused",6:"TTL expired",7:"command unsupported",8:"address type unsupported"}[code] }

type socksUDPConn struct { *net.UDPConn; control net.Conn; once sync.Once }
func (c *socksUDPConn) WriteTo(b []byte, addr net.Addr) (int,error) { u,ok:=addr.(*net.UDPAddr); if !ok{return 0,fmt.Errorf("SOCKS UDP destination must be UDP address")}; p:=&ParentProxy{}; h,err:=p.requestAddress(u.String()); if err!=nil{return 0,err}; packet:=append([]byte{0,0,0},h...); packet=append(packet,b...); if _,err=c.UDPConn.Write(packet);err!=nil{return 0,err}; return len(b),nil }
func (c *socksUDPConn) ReadFrom(b []byte) (int,net.Addr,error) { packet:=make([]byte,len(b)+262); n,err:=c.UDPConn.Read(packet); if err!=nil{return 0,nil,err}; if n<4 || packet[0]!=0 || packet[1]!=0 || packet[2]!=0{return 0,nil,fmt.Errorf("invalid SOCKS UDP packet")}; pos:=4; var ip net.IP; switch packet[3] { case 1: if n<pos+4+2{return 0,nil,io.ErrUnexpectedEOF}; ip=append(net.IP(nil),packet[pos:pos+4]...);pos+=4; case 4: if n<pos+16+2{return 0,nil,io.ErrUnexpectedEOF};ip=append(net.IP(nil),packet[pos:pos+16]...);pos+=16; default:return 0,nil,fmt.Errorf("unsupported SOCKS UDP response address type") }; port:=int(binary.BigEndian.Uint16(packet[pos:pos+2]));pos+=2; copied:=copy(b,packet[pos:n]);return copied,&net.UDPAddr{IP:ip,Port:port},nil }
func (c *socksUDPConn) Close() error { var err error;c.once.Do(func(){err=c.UDPConn.Close();_ = c.control.Close()});return err }
func (c *socksUDPConn) SetDeadline(t time.Time) error{return c.UDPConn.SetDeadline(t)}
