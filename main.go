package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

var bootnode = "enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303"

func main() {

	// marshal node into usable enode struct.
	TargetNode, err := enode.Parse(enode.ValidSchemes, bootnode)
	if err != nil {
		log.Fatalf("Failed to parse bootnode: %s", err.Error())
	}

	// start ephemeral discovery node.
	disc, _ := startV4("", bootnode, "", "")
	defer disc.Close()

	// resolve node.
	// resolvedNode := disc.Resolve(TargetNode)
	// if resolvedNode != nil {
	// 	log.Println("Found node:", resolvedNode.String())
	// } else {
	// 	log.Println("No node found with the target ID.")
	// }
	// Discover neighbors of a node.
	neighbors := disc.LookupPubkey(TargetNode.Pubkey())
	fmt.Printf("Found %v neighbors.\n", len(neighbors))
	for _, neighbor := range neighbors {
		fmt.Println(neighbor.String())
	}
}

// startV4 starts an ephemeral discovery V4 node.
func startV4(nodekey, bootnodes, nodedb, extaddr string) (*discover.UDPv4, discover.Config) {
	ln, config := makeDiscoveryConfig(nodekey, bootnodes, nodedb)
	socket := listen(ln, extaddr)
	disc, err := discover.ListenV4(socket, ln, config)
	if err != nil {
		exit(err)
	}
	return disc, config
}

// makeDiscoveryConfig creates a discovery configuration.
// A discovery configuration is used to create a discovery node.
func makeDiscoveryConfig(nodekey, bootnodes, nodedb string) (*enode.LocalNode, discover.Config) {
	var cfg discover.Config

	if nodekey != "" {
		key, err := crypto.HexToECDSA(nodekey)
		if err != nil {
			exit(fmt.Errorf("-%s: %v", nodekey, err))
		}
		cfg.PrivateKey = key
	} else {
		cfg.PrivateKey, _ = crypto.GenerateKey()
	}

	if bootnodes != "" {
		bn, err := parseBootnodes(bootnodes)
		if err != nil {
			exit(err)
		}
		cfg.Bootnodes = bn
	}

	dbpath := nodedb
	db, err := enode.OpenDB(dbpath)
	if err != nil {
		exit(err)
	}
	ln := enode.NewLocalNode(db, cfg.PrivateKey)
	return ln, cfg
}

func listen(ln *enode.LocalNode, extAddr string) *net.UDPConn {
	addr := "0.0.0.0:0"
	socket, err := net.ListenPacket("udp4", addr)
	if err != nil {
		exit(err)
	}

	// Configure UDP endpoint in ENR from listener address.
	usocket := socket.(*net.UDPConn)
	uaddr := socket.LocalAddr().(*net.UDPAddr)
	if uaddr.IP.IsUnspecified() {
		ln.SetFallbackIP(net.IP{127, 0, 0, 1})
	} else {
		ln.SetFallbackIP(uaddr.IP)
	}
	ln.SetFallbackUDP(uaddr.Port)

	if extAddr != "" {
		ip, port, ok := parseExtAddr(extAddr)
		if !ok {
			exit(fmt.Errorf("invalid external address %q", extAddr))
		}
		ln.SetStaticIP(ip)
		if port != 0 {
			ln.SetFallbackUDP(port)
		}
	}

	return usocket
}

// exit prints the error to stderr and exits with status 1.
func exit(err interface{}) {
	if err == nil {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// parseExtAddr parses an external address specification.
func parseExtAddr(spec string) (ip net.IP, port int, ok bool) {
	ip = net.ParseIP(spec)
	if ip != nil {
		return ip, 0, true
	}
	host, portstr, err := net.SplitHostPort(spec)
	if err != nil {
		return nil, 0, false
	}
	ip = net.ParseIP(host)
	if ip == nil {
		return nil, 0, false
	}
	port, err = strconv.Atoi(portstr)
	if err != nil {
		return nil, 0, false
	}
	return ip, port, true
}

// parseBootnodes parses a comma-separated list of bootnodes.
func parseBootnodes(bootNodes string) ([]*enode.Node, error) {
	s := params.MainnetBootnodes
	if bootNodes != "" {
		input := bootNodes
		if input == "" {
			return nil, nil
		}
		s = strings.Split(input, ",")
	}
	nodes := make([]*enode.Node, len(s))
	var err error
	for i, record := range s {
		nodes[i], err = parseNode(record)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap node: %v", err)
		}
	}
	return nodes, nil
}

// parseNode parses a node record and verifies its signature.
func parseNode(source string) (*enode.Node, error) {
	if strings.HasPrefix(source, "enode://") {
		return enode.ParseV4(source)
	}
	r, err := parseRecord(source)
	if err != nil {
		return nil, err
	}
	return enode.New(enode.ValidSchemes, r)
}

// pulled from enrcmd.go in dsp2p cli library.
// parseRecord parses a node record from hex, base64, or raw binary input.
func parseRecord(source string) (*enr.Record, error) {
	bin := []byte(source)
	if d, ok := decodeRecordHex(bytes.TrimSpace(bin)); ok {
		bin = d
	} else if d, ok := decodeRecordBase64(bytes.TrimSpace(bin)); ok {
		bin = d
	}
	var r enr.Record
	err := rlp.DecodeBytes(bin, &r)
	return &r, err
}

// decodeRecordHex decodes a hex-encoded node record.
func decodeRecordHex(b []byte) ([]byte, bool) {
	if bytes.HasPrefix(b, []byte("0x")) {
		b = b[2:]
	}
	dec := make([]byte, hex.DecodedLen(len(b)))
	_, err := hex.Decode(dec, b)
	return dec, err == nil
}

// decodeRecordBase64 decodes a base64-encoded node record.
func decodeRecordBase64(b []byte) ([]byte, bool) {
	if bytes.HasPrefix(b, []byte("enr:")) {
		b = b[4:]
	}
	dec := make([]byte, base64.RawURLEncoding.DecodedLen(len(b)))
	n, err := base64.RawURLEncoding.Decode(dec, b)
	return dec[:n], err == nil
}
