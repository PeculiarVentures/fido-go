// Package reportdesc parses the bounded subset of HID descriptors needed for
// collection inventory and unambiguous fixed-size Input/Output reports.
package reportdesc

import (
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// Description contains all top-level Application collections in descriptor order.
type Description struct{ Collections []Collection }

// Collection describes an addressable Application collection. Unsupported
// collections remain visible in inventory, but must not be opened for I/O.
type Collection struct {
	Index     int
	Usage     driver.Usage
	Layout    driver.Layout
	Supported bool
}

type globals struct{ page, size, count, id uint32 }
type reports struct {
	input, output map[uint8]uint64
	unsupported   bool
}
type parser struct {
	result        Description
	reports       []reports
	global        globals
	stack         []globals
	collections   []int
	usages        []uint32
	minimum       uint32
	hasMinimum    bool
	invalidLayout bool
}

// Parse validates descriptor bounds and calculates fixed-size report layouts.
// Report sizes exclude the Report ID. Shared IDs across collections are rejected
// for I/O, because a native channel cannot demultiplex them safely.
func Parse(data []byte) (Description, error) {
	if len(data) == 0 || len(data) > driver.MaxDescriptorSize {
		return Description{}, invalid("descriptor size")
	}
	p := parser{}
	for pos := 0; pos < len(data); {
		prefix := data[pos]
		pos++
		if prefix == 0xfe {
			return Description{}, invalid("long item unsupported")
		}
		size := int(prefix & 3)
		if size == 3 {
			size = 4
		}
		if size > len(data)-pos {
			return Description{}, invalid("truncated item")
		}
		var value uint32
		for i := 0; i < size; i++ {
			value |= uint32(data[pos+i]) << (8 * i)
		}
		pos += size
		var err error
		switch (prefix >> 2) & 3 {
		case 0:
			err = p.main(prefix>>4, value)
		case 1:
			err = p.globalItem(prefix>>4, value)
		case 2:
			switch prefix >> 4 {
			case 0:
				if len(p.usages) >= 1024 {
					err = invalid("too many local usages")
				} else {
					p.usages = append(p.usages, value)
				}
			case 1:
				p.minimum, p.hasMinimum = value, true
			case 2:
				if !p.hasMinimum || value < p.minimum {
					err = invalid("invalid usage range")
				}
			case 10:
				err = invalid("usage delimiters unsupported")
			}
		default:
			err = invalid("reserved item type")
		}
		if err != nil {
			return Description{}, err
		}
	}
	if len(p.collections) != 0 || len(p.stack) != 0 {
		return Description{}, invalid("unbalanced descriptor")
	}
	p.finish()
	return p.result, nil
}

func (p *parser) globalItem(tag uint8, value uint32) error {
	switch tag {
	case 0:
		if value > 0xffff {
			return invalid("usage page exceeds 16 bits")
		}
		p.global.page = value
	case 7:
		p.global.size = value
	case 8:
		if value > 255 {
			return invalid("invalid report ID")
		}
		if value == 0 {
			// Explicit Report ID zero is invalid for I/O, but its framing is
			// safely parseable and must not hide known inventory usages.
			p.invalidLayout = true
		}
		p.global.id = value
	case 9:
		p.global.count = value
	case 10:
		if len(p.stack) == 32 {
			return invalid("global stack depth")
		}
		p.stack = append(p.stack, p.global)
	case 11:
		if len(p.stack) == 0 {
			return invalid("global stack underflow")
		}
		p.global = p.stack[len(p.stack)-1]
		p.stack = p.stack[:len(p.stack)-1]
	}
	return nil
}

func (p *parser) main(tag uint8, value uint32) error {
	defer func() { p.usages = nil; p.hasMinimum = false }()
	current := -1
	if len(p.collections) != 0 {
		current = p.collections[len(p.collections)-1]
	}
	switch tag {
	case 10:
		if len(p.collections) == 32 {
			return invalid("collection depth")
		}
		if len(p.collections) == 0 && value == 1 {
			if len(p.result.Collections) == 256 {
				return invalid("too many collections")
			}
			usage := p.minimum
			if len(p.usages) != 0 {
				usage = p.usages[0]
			}
			page := p.global.page
			if usage > 0xffff {
				page = usage >> 16
			}
			current = len(p.result.Collections)
			p.result.Collections = append(p.result.Collections, Collection{Index: current, Usage: driver.Usage{Page: uint16(page), ID: uint16(usage)}})
			p.reports = append(p.reports, reports{input: make(map[uint8]uint64), output: make(map[uint8]uint64)})
		}
		p.collections = append(p.collections, current)
	case 12:
		if len(p.collections) == 0 {
			return invalid("collection underflow")
		}
		p.collections = p.collections[:len(p.collections)-1]
	case 8, 9, 11:
		bits := uint64(p.global.size) * uint64(p.global.count)
		if bits > uint64(driver.MaxReportSize)*8 {
			return invalid("report exceeds size limit")
		}
		if current < 0 {
			return invalid("report outside Application collection")
		}
		if tag == 11 {
			return nil
		}
		target := p.reports[current].input
		if tag == 9 {
			target = p.reports[current].output
		}
		id := uint8(p.global.id)
		if target[id] > uint64(driver.MaxReportSize)*8-bits {
			return invalid("report exceeds size limit")
		}
		target[id] += bits
	}
	return nil
}

func (p *parser) finish() {
	// IDs are direction-specific. Sharing in either direction makes both
	// collections unsafe, even when their report lengths happen to match.
	inOwners, outOwners := map[uint8]int{}, map[uint8]int{}
	for i, r := range p.reports {
		c := &p.result.Collections[i]
		c.Supported = !p.invalidLayout && len(r.input) == 1 && len(r.output) == 1
		for id, bits := range r.input {
			c.Layout.Input = driver.ReportSpec{ID: id, Size: int((bits + 7) / 8)}
			if bits == 0 {
				c.Supported = false
			}
			if owner, exists := inOwners[id]; exists {
				p.reports[owner].unsupported = true
				p.reports[i].unsupported = true
			} else {
				inOwners[id] = i
			}
		}
		for id, bits := range r.output {
			c.Layout.Output = driver.ReportSpec{ID: id, Size: int((bits + 7) / 8)}
			if bits == 0 {
				c.Supported = false
			}
			if owner, exists := outOwners[id]; exists {
				p.reports[owner].unsupported = true
				p.reports[i].unsupported = true
			} else {
				outOwners[id] = i
			}
		}
	}
	// Report-ID framing is shared by a native channel. An unnumbered
	// collection cannot safely coexist with numbered siblings in a direction.
	_, zeroInput := inOwners[0]
	_, zeroOutput := outOwners[0]
	for i := range p.reports {
		if zeroInput && len(inOwners) > 1 && len(p.reports[i].input) > 0 ||
			zeroOutput && len(outOwners) > 1 && len(p.reports[i].output) > 0 {
			p.reports[i].unsupported = true
		}
	}
	for i := range p.reports {
		if p.reports[i].unsupported {
			p.result.Collections[i].Supported = false
		}
	}
}

func invalid(message string) error {
	return &driver.Error{Op: "parse descriptor", Kind: driver.KindUnsupported, Message: fmt.Sprintf("invalid or unsupported HID descriptor: %s", message)}
}
