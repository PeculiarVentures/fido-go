package reportdesc

import "github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"

const maxCollections = 256

// Inventory resolves top-level Application collection usages for inventory.
// It first applies the strict Parse. When the strict layout rules reject a
// descriptor, it falls back to a usage-only scan, so a device whose reports
// cannot be used for I/O still has known usages and does not make an
// inventory snapshot incomplete. Fallback collections are never Supported;
// layoutErr then explains why. A non-nil error with no collections means the
// descriptor's item stream itself could not be read.
func Inventory(data []byte) (desc Description, layoutErr error) {
	desc, err := Parse(data)
	if err == nil {
		return desc, nil
	}
	fallback, scanErr := scanUsages(data)
	if scanErr != nil || len(fallback.Collections) == 0 {
		return Description{}, err
	}
	return fallback, err
}

// scanUsages reads only the item framing, usage pages, local usages and
// collection nesting. Report sizes, delimiters, long items and reports outside
// Application collections do not affect top-level usages and are ignored.
func scanUsages(data []byte) (Description, error) {
	if len(data) == 0 || len(data) > driver.MaxDescriptorSize {
		return Description{}, invalid("descriptor size")
	}
	var (
		result  Description
		page    uint32
		stack   []uint32
		usages  int
		first   uint32
		minimum uint32
		hasMin  bool
		depth   int
	)
	resetLocals := func() { usages, hasMin = 0, false }
	for pos := 0; pos < len(data); {
		prefix := data[pos]
		pos++
		if prefix == 0xfe {
			if len(data)-pos < 2 {
				return Description{}, invalid("truncated long item")
			}
			size := int(data[pos])
			pos += 2
			if size > len(data)-pos {
				return Description{}, invalid("truncated long item")
			}
			pos += size
			continue
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
		tag := prefix >> 4
		switch (prefix >> 2) & 3 {
		case 0: // main
			switch tag {
			case 10:
				if depth == 0 && value == 1 {
					if len(result.Collections) == maxCollections {
						return Description{}, invalid("too many collections")
					}
					usage := minimum
					if usages != 0 || !hasMin {
						usage = first
					}
					collectionPage := page & 0xffff
					if usage > 0xffff {
						collectionPage = usage >> 16
					}
					result.Collections = append(result.Collections, Collection{Index: len(result.Collections), Usage: driver.Usage{Page: uint16(collectionPage), ID: uint16(usage)}})
				}
				depth++
			case 12:
				if depth > 0 {
					depth--
				}
			}
			resetLocals()
		case 1: // global
			switch tag {
			case 0:
				page = value
			case 10:
				if len(stack) < 32 {
					stack = append(stack, page)
				}
			case 11:
				if len(stack) > 0 {
					page = stack[len(stack)-1]
					stack = stack[:len(stack)-1]
				}
			}
		case 2: // local
			switch tag {
			case 0:
				if usages == 0 {
					first = value
				}
				usages++
			case 1:
				minimum, hasMin = value, true
			}
		}
	}
	return result, nil
}
