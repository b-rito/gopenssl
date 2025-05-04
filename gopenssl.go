package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

var (
	connect string
	servername string
	noverify bool
)

// Exported *before* root.go tries to use it
var rootCmd = &cobra.Command{
    Use:   "gopenssl --connect host:port --servername hostname",
    Short: "Check the TCP/TLS connectivity to an endpoint",
    Args:  cobra.NoArgs,
    Run: func(cmd *cobra.Command, args []string) {
    },
}

func init() {
	rootCmd.Flags().StringVarP(&connect, "connect", "c", "", "Target host:port")
    rootCmd.Flags().StringVarP(&servername, "servername", "s", "", "Servername for TLS/SSL")
    rootCmd.Flags().BoolVar(&noverify, "noverify", false, "Do not verify TLS/SSL (Use if certificate expired)")
    rootCmd.MarkFlagRequired("connect")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
    }

	// Verify connect format
	if connect == "" {
		fmt.Println("Error: --connect is required in format, host:port")
		os.Exit(1)
	}

	// Split 'connect' to get host + port and verify port
	parts := strings.Split(connect, ":")
	if len(parts) != 2 {
		fmt.Println("Error: --connect must be in host:port format")
		os.Exit(1)
	}

	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil || port <= 0 || port > 65535 {
		fmt.Println("Error: Invalid port number")
		os.Exit(1)
	}

	// Resolve host to IP for output
	resolvedIp, err := net.LookupIP(host)
	if err != nil {
		fmt.Printf("Error resolving hostname: %v\n", err)
	}
	fmt.Println("Connecting to", resolvedIp[0].String())

	// Format address for TLS
	address := fmt.Sprintf("%s:%d", host, port)

	var server string
	if servername != "" {
		server = servername
	} else {
		server = host
	}

	var configs []TlsOptionsStruct
	if noverify {
		configs = []TlsOptionsStruct {
			{"TLS1.0", &tls.Config{InsecureSkipVerify: false, ServerName: server, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10}},
			{"TLS1.1", &tls.Config{InsecureSkipVerify: false, ServerName: server, MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11}},
			{"TLS1.2", &tls.Config{InsecureSkipVerify: false, ServerName: server, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}},
			{"TLS1.3", &tls.Config{InsecureSkipVerify: false, ServerName: server, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}},
		}
	} else {
		configs = []TlsOptionsStruct {
			{"TLS1.0", &tls.Config{InsecureSkipVerify: true, ServerName: server, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10}},
			{"TLS1.1", &tls.Config{InsecureSkipVerify: true, ServerName: server, MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11}},
			{"TLS1.2", &tls.Config{InsecureSkipVerify: true, ServerName: server, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}},
			{"TLS1.3", &tls.Config{InsecureSkipVerify: true, ServerName: server, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}},
		}
	}
	
    results := PingManager(address, configs)
    for _, res := range results {
        if res.Success {
            fmt.Printf("[%s] Success - RTT: %v\n", res.Version, res.RTT)
        } else {
            fmt.Printf("[%s] Failed - %v\n", res.Version, res.Error)
        }
    }

	// Connect with either Host-from_connect or Server-from_servername
	// If conn fails with servername, try with insecureskipverify
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{ServerName: server})
	if err != nil {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{ServerName: server, InsecureSkipVerify: true})
		if err != nil {
			fmt.Printf("InsecureSkipVerify: True - error: %v\n", err)
		}
		if conn != nil {
			defer conn.Close()
		}
	}
	if conn != nil {
		defer conn.Close()
	}

	// Brief connect information
	// Connect RemoteAddr && Servername verify 
	fmt.Println("\n==========")
	fmt.Println()
	fmt.Printf("Connected to %s\n", conn.RemoteAddr())
	fmt.Printf("Servername %s ", server)

	// VerifyHostname formatting
	err = conn.VerifyHostname(server)
	if err != nil {
		fmt.Printf("failed verification: %v\n", err)
	} else {
		fmt.Printf("is valid for certificate\n")
	}
	fmt.Println()

	printCertificateChain(conn.ConnectionState())
}

func PingManager(address string, configs []TlsOptionsStruct) []PingResult {
    var wg sync.WaitGroup
    resultsChan := make(chan PingResult)

	// Loop configs to make each connection for each TLS version
    for _, conf := range configs {
        wg.Add(1)
        go func(version string, config *tls.Config) {
            defer wg.Done()
            start := time.Now()

            conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, config)
            elapsed := time.Since(start)
            if err != nil {
                resultsChan <- PingResult{Success: false, RTT: elapsed, Error: err, Version: version}
                return
            }
			if conn != nil {
				conn.Close()
			}
            resultsChan <- PingResult{Success: true, RTT: elapsed, Version: version}
        }(conf.Name, conf.Config)
    }

    // Close resultsChan when connections complete
    go func() {
        wg.Wait()
        close(resultsChan)
    }()

    // Collect results
    var results []PingResult
    for res := range resultsChan {
        results = append(results, res)
    }

    // Sort results by ConfigName (or Address, RTT, etc.)
    sort.Slice(results, func(i, j int) bool {
        return results[i].Version < results[j].Version
    })

    return results
}

func printCertificateChain(state tls.ConnectionState) {
	fmt.Printf("==========\n\n")
	fmt.Printf("Certificate chain\n")

    for i, cert := range state.PeerCertificates {
        fmt.Printf(" %d s:%s\n", i, cert.Subject.String())
        fmt.Printf("   i:%s\n", cert.Issuer.String())

        // Public key info
        keySize := getKeySize(cert)
        fmt.Printf("   a:PKEY: %s, %d (bit); sigalg: %s\n", publicKeyLabel(cert.PublicKeyAlgorithm), keySize, cert.SignatureAlgorithm)

        // Validity
        fmt.Printf("   v:NotBefore: %s; NotAfter: %s\n",
            cert.NotBefore.UTC().Format("Jan 2 15:04:05 2006 UTC"),
            cert.NotAfter.UTC().Format("Jan 2 15:04:05 2006 UTC"))

        // SANs
        for _, san := range cert.DNSNames {
            fmt.Printf("   SAN: %s\n", san)
        }
        for _, ip := range cert.IPAddresses {
            fmt.Printf("   SAN IP: %s\n", ip.String())
        }
    }
	fmt.Println()
	fmt.Printf("Negotiated TLS Version\n")
    fmt.Printf("   TLS Version: %s\n", tlsVersionToString(state.Version))
    fmt.Printf("   Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
}

func getKeySize(cert *x509.Certificate) int {
    switch pub := cert.PublicKey.(type) {
    case *rsa.PublicKey:
        return pub.N.BitLen()
    case *ecdsa.PublicKey:
        return pub.Params().BitSize
    case ed25519.PublicKey:
        return len(pub) * 8
    default:
        return 0
    }
}

func tlsVersionToString(version uint16) string {
    switch version {
    case tls.VersionTLS13:
        return "TLS 1.3"
    case tls.VersionTLS12:
        return "TLS 1.2"
    case tls.VersionTLS11:
        return "TLS 1.1"
    case tls.VersionTLS10:
        return "TLS 1.0"
    default:
        return fmt.Sprintf("Unknown (0x%x)", version)
    }
}

func publicKeyLabel(algo x509.PublicKeyAlgorithm) string {
    switch algo {
    case x509.RSA:
        return "rsaEncryption"
    case x509.ECDSA:
        return "id-ecPublicKey"
    case x509.Ed25519:
        return "id-Ed25519"
    default:
        return algo.String() // fallback
    }
}

type PingJob struct {
	Address string
	TLSConfig *tls.Config
}

type PingResult struct {
	Success bool
	RTT time.Duration
	Error error
	Version string
}

type TlsOptionsStruct struct {
	Name string
	Config *tls.Config
}