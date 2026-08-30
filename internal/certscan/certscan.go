// Package certscan extracts candidate hostnames from Certificate
// Transparency log entries.
package certscan

import (
	"fmt"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"

	"github.com/kenjoe41/Roots/internal/loglist"
)

// Leaf parses the certificate carried by a raw CT log entry.
//
// MerkleTreeLeaf.X509Certificate only works for ct.X509LogEntryType entries
// and returns an error for precertificates; MerkleTreeLeaf.Precertificate is
// the mirror image. Most log entries are precertificates (a CA logs the
// precert to obtain an embedded SCT before issuing the final certificate,
// and many are never re-submitted as a final cert), so the entry type must
// be checked before picking the accessor - calling the wrong one for every
// entry silently drops every precertificate a log has.
func Leaf(rawEntry *ct.RawLogEntry) (*x509.Certificate, error) {
	switch rawEntry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		return rawEntry.Leaf.X509Certificate()
	case ct.PrecertLogEntryType:
		return rawEntry.Leaf.Precertificate()
	default:
		return nil, fmt.Errorf("unknown CT log entry type: %v", rawEntry.Leaf.TimestampedEntry.EntryType)
	}
}

// Hostnames returns every syntactically valid hostname referenced anywhere
// in c: the Subject CommonName, every SAN dNSName and
// uniformResourceIdentifier entry, the domain half of SAN rfc822Name (email)
// entries, and - for constrained CA certificates, which do show up in CT
// logs alongside leaf certs - the Name Constraints extension's permitted
// and excluded DNS domains. Results are neither deduplicated nor sorted;
// the same hostname can appear more than once if it's referenced in more
// than one field.
func Hostnames(c *x509.Certificate) []string {
	var hosts []string
	add := func(h string) {
		if h != "" && loglist.ValidHostname(h) {
			hosts = append(hosts, h)
		}
	}

	add(c.Subject.CommonName)

	for _, name := range c.DNSNames {
		add(name)
	}

	for _, uri := range c.URIs {
		add(uri.Hostname())
	}

	for _, email := range c.EmailAddresses {
		if _, domain, ok := strings.Cut(email, "@"); ok {
			add(domain)
		}
	}

	for _, domain := range c.PermittedDNSDomains {
		add(domain)
	}
	for _, domain := range c.ExcludedDNSDomains {
		add(domain)
	}

	return hosts
}
