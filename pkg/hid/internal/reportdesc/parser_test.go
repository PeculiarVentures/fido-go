package reportdesc

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"testing"
)

// One FIDO application, nine input and output bits, rounded up to two bytes.
var descriptor = []byte{0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x75, 0x03, 0x95, 0x03, 0x81, 0x02, 0x91, 0x02, 0xc0}

func TestParseLayoutAndBounds(t *testing.T) {
	d, err := Parse(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Collections) != 1 || !d.Collections[0].Supported || d.Collections[0].Usage != (driver.Usage{Page: 0xf1d0, ID: 1}) || d.Collections[0].Layout.Input.Size != 2 || d.Collections[0].Layout.Output.Size != 2 {
		t.Fatalf("unexpected description: %+v", d)
	}
	cases := map[string][]byte{"empty": nil, "truncated": {0x06, 1}, "long": {0xfe}, "pop underflow": {0xb4}, "unclosed push": {0xa4}, "unclosed collection": {0xa1, 1}, "end underflow": {0xc0}, "oversize": append(append([]byte{}, descriptor[:7]...), 0x77, 0xff, 0xff, 0xff, 0xff, 0x97, 0xff, 0xff, 0xff, 0xff, 0x81, 2, 0xc0), "descriptor limit": make([]byte, driver.MaxDescriptorSize+1)}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(in); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
func TestParseSharedReportIDsUnsupported(t *testing.T) {
	both := append(append([]byte{}, descriptor...), descriptor...)
	d, err := Parse(both)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Collections) != 2 || d.Collections[0].Supported || d.Collections[1].Supported {
		t.Fatalf("shared reports accepted: %+v", d)
	}
}
func FuzzParse(f *testing.F) {
	f.Add(descriptor)
	f.Add([]byte{0xfe, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Parse(data)
		if err == nil {
			for _, c := range d.Collections {
				if c.Layout.Input.Size > driver.MaxReportSize || c.Layout.Output.Size > driver.MaxReportSize {
					t.Fatal("report exceeds bound")
				}
			}
		}
	})
}

func TestParseInventoryRetainsApplicationsWithInvalidZeroReportID(t *testing.T) {
	for _, usage := range []byte{1, 5} {
		data := []byte{0x06, 0x0c, 0xff, 0x09, usage, 0xa1, 0x01, 0x85, 0x00, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x05, 0x81, 0x02, 0xc0}
		d, err := Parse(data)
		if err != nil || len(d.Collections) != 1 || d.Collections[0].Supported || d.Collections[0].Usage != (driver.Usage{Page: 0xff0c, ID: uint16(usage)}) {
			t.Fatalf("usage %d: %+v %v", usage, d, err)
		}
	}
}

func TestParseNestedCollectionAndGlobalPushPop(t *testing.T) {
	// Inner physical collection inherits the parent Application and a pushed
	// report size is restored before output, giving 2 input bytes and 1 output.
	data := []byte{0x06, 0xd0, 0xf1, 0x09, 1, 0xa1, 1, 0x75, 8, 0x95, 1, 0xa4, 0x75, 16, 0x09, 2, 0xa1, 0, 0x81, 2, 0xc0, 0xb4, 0x91, 2, 0xc0}
	d, err := Parse(data)
	if err != nil || len(d.Collections) != 1 || !d.Collections[0].Supported || d.Collections[0].Layout.Input.Size != 2 || d.Collections[0].Layout.Output.Size != 1 {
		t.Fatalf("%+v %v", d, err)
	}
}
func TestParseMixedNumberedAndUnnumberedCollectionsUnsupported(t *testing.T) {
	numbered := append([]byte{}, descriptor[:7]...)
	numbered = append(numbered, 0x85, 1)
	numbered = append(numbered, descriptor[7:]...)
	data := append(append([]byte{}, descriptor...), numbered...)
	d, err := Parse(data)
	if err != nil || len(d.Collections) != 2 || d.Collections[0].Supported || d.Collections[1].Supported {
		t.Fatalf("%+v %v", d, err)
	}
}
