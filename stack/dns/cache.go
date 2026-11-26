package dns

import (
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// question is a DNS question as questions compare: its name in lower case.
type question struct {
	name  string
	typ   dnsmessage.Type
	class dnsmessage.Class
}

// key is what tells the answers of one upstream apart: the question and, of its query, the RD and CD flags, whether it carries an OPT record and the DO bit of that record.
type key struct {
	question
	rd, cd, edns, do bool
}

// queryKey gives no datagram a key: the ABSENT variant tells no queries apart.
func queryKey([]byte) (uint16, key, bool) {
	return 0, key{}, false
}

// lifetime gives no reply a lifetime: the ABSENT variant stores none.
func lifetime([]byte, uint16, question) time.Duration {
	return 0
}

// cache keeps nothing in the ABSENT variant: size and now are only what the tests set.
type cache struct {
	size int
	now  func() time.Time
}

// limit knows no size and no default.
func (c *cache) limit() int {
	return 0
}

// put keeps nothing.
func (c *cache) put(string, key, []byte, time.Duration) {}

// get answers nothing.
func (c *cache) get(string, key, []byte) ([]byte, bool) {
	return nil, false
}
