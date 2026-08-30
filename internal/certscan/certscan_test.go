package certscan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"sort"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

// oidCTPoison is the CT poison extension (RFC 6962 s3.1), used to mark a
// certificate as a precertificate.
var oidCTPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// buildLeaf signs a certificate template with the given SAN fields using a
// throwaway self-signed issuer, optionally marking it as a precertificate
// (poison extension present), and returns it parsed as ct-go's x509 type
// alongside the issuer, ready to feed to ct.MerkleTreeLeafFromChain.
func buildLeaf(t *testing.T, cn string, dnsNames []string, uris []string, emails []string, precert bool) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	issuerTemplate := &stdx509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(0, 0).Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              stdx509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	issuerDER, err := stdx509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("creating issuer cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}

	var parsedURIs []*url.URL
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parsing test URI %q: %v", u, err)
		}
		parsedURIs = append(parsedURIs, parsed)
	}

	leafTemplate := &stdx509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Unix(0, 0),
		NotAfter:       time.Unix(0, 0).Add(24 * time.Hour),
		DNSNames:       dnsNames,
		EmailAddresses: emails,
		URIs:           parsedURIs,
	}
	if precert {
		leafTemplate.ExtraExtensions = []pkix.Extension{
			{Id: oidCTPoison, Critical: true, Value: []byte{0x05, 0x00}},
		}
	}

	leafDER, err := stdx509.CreateCertificate(rand.Reader, leafTemplate, issuerTemplate, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing leaf cert with ct-go x509: %v", err)
	}
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parsing issuer cert with ct-go x509: %v", err)
	}
	return leafCert, issuerCert
}

func rawEntryFor(t *testing.T, leaf, issuer *x509.Certificate, etype ct.LogEntryType) *ct.RawLogEntry {
	t.Helper()

	chain := []*x509.Certificate{leaf}
	if etype == ct.PrecertLogEntryType {
		chain = append(chain, issuer)
	}

	merkleLeaf, err := ct.MerkleTreeLeafFromChain(chain, etype, 0)
	if err != nil {
		t.Fatalf("building merkle leaf: %v", err)
	}
	return &ct.RawLogEntry{Index: 0, Leaf: *merkleLeaf}
}

func TestLeaf_X509Entry(t *testing.T) {
	leaf, issuer := buildLeaf(t, "www.example.com", []string{"api.example.com"}, nil, nil, false)
	rawEntry := rawEntryFor(t, leaf, issuer, ct.X509LogEntryType)

	got, err := Leaf(rawEntry)
	if err != nil {
		t.Fatalf("Leaf() on an X509LogEntryType entry: %v", err)
	}
	if got.Subject.CommonName != "www.example.com" {
		t.Errorf("CommonName = %q, want www.example.com", got.Subject.CommonName)
	}
}

// TestLeaf_PrecertEntry is the regression test for the bug this package
// fixes: calling MerkleTreeLeaf.X509Certificate() on a precertificate entry
// always errors, so every precert in a log was silently skipped before
// Leaf() dispatched on entry type. This proves precert entries now parse.
func TestLeaf_PrecertEntry(t *testing.T) {
	leaf, issuer := buildLeaf(t, "precert.example.com", []string{"api-precert.example.com"}, nil, nil, true)
	rawEntry := rawEntryFor(t, leaf, issuer, ct.PrecertLogEntryType)

	got, err := Leaf(rawEntry)
	if err != nil {
		t.Fatalf("Leaf() on a PrecertLogEntryType entry: %v", err)
	}
	if got.Subject.CommonName != "precert.example.com" {
		t.Errorf("CommonName = %q, want precert.example.com", got.Subject.CommonName)
	}
	if len(got.DNSNames) != 1 || got.DNSNames[0] != "api-precert.example.com" {
		t.Errorf("DNSNames = %v, want [api-precert.example.com]", got.DNSNames)
	}
}

func TestHostnames_CoversAllSANTypes(t *testing.T) {
	leaf, issuer := buildLeaf(t,
		"www.example.com",
		[]string{"api.example.com", "*.wild.example.com"},
		[]string{"https://uri.example.com:8443/path"},
		[]string{"admin@mail.example.com"},
		false,
	)
	rawEntry := rawEntryFor(t, leaf, issuer, ct.X509LogEntryType)

	parsed, err := Leaf(rawEntry)
	if err != nil {
		t.Fatalf("Leaf(): %v", err)
	}

	got := Hostnames(parsed)
	sort.Strings(got)

	want := []string{
		"*.wild.example.com",
		"api.example.com",
		"mail.example.com",
		"uri.example.com",
		"www.example.com",
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("Hostnames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Hostnames()[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], want[i], got, want)
		}
	}
}

func TestHostnames_SkipsInvalidValues(t *testing.T) {
	leaf, issuer := buildLeaf(t, "", nil, nil, nil, false)
	rawEntry := rawEntryFor(t, leaf, issuer, ct.X509LogEntryType)

	parsed, err := Leaf(rawEntry)
	if err != nil {
		t.Fatalf("Leaf(): %v", err)
	}

	if got := Hostnames(parsed); len(got) != 0 {
		t.Errorf("Hostnames() on a cert with no SANs and empty CN = %v, want empty", got)
	}
}
