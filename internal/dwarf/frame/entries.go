// nolint:stylecheck,deadcode,varcheck
package frame

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// CommonInformationEntry represents a Common Information Entry in
// the Dwarf .debug_frame section.
type CommonInformationEntry struct {
	Length              uint32
	CIE_id              uint32
	Version             uint8
	Augmentation        string
	CodeAlignmentFactor uint64
	DataAlignmentFactor int64
	// 返回地址寄存器
	ReturnAddressRegister uint64
	//指令
	InitialInstructions []byte
	staticBase          uint64

	// eh_frame pointer encoding
	ptrEncAddr ptrEnc
}

// FrameDescriptionEntry represents a Frame Descriptor Entry in the
// Dwarf .debug_frame section.
type FrameDescriptionEntry struct {
	Length uint32
	// 所属的CIE
	CIE          *CommonInformationEntry
	Instructions []byte
	// begin是开始的pc地址，
	begin, size uint64
	order       binary.ByteOrder
}

// Cover returns whether or not the given address is within the
// bounds of this frame.
func (fde *FrameDescriptionEntry) Cover(addr uint64) bool {
	return (addr - fde.begin) < fde.size
}

// Begin returns address of first location for this frame.
func (fde *FrameDescriptionEntry) Begin() uint64 {
	return fde.begin
}

// End returns address of last location for this frame.
func (fde *FrameDescriptionEntry) End() uint64 {
	// frame 开始的地方
	return fde.begin + fde.size
}

// Translate moves the beginning of fde forward by delta.
func (fde *FrameDescriptionEntry) Translate(delta uint64) {
	fde.begin += delta
}

// 栈帧描述entries
type FrameDescriptionEntries []*FrameDescriptionEntry

func (t FrameDescriptionEntries) Len() int           { return len(t) }
func (t FrameDescriptionEntries) Less(i, j int) bool { return t[i].begin < t[j].begin }
func (t FrameDescriptionEntries) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

func newFrameIndex() FrameDescriptionEntries {
	return make(FrameDescriptionEntries, 0, 1000)
}

// ErrNoFDEForPCError FDE for PC not found error.
type ErrNoFDEForPCError struct {
	PC uint64
}

func (err *ErrNoFDEForPCError) Error() string {
	return fmt.Sprintf("could not find FDE for PC %#v", err.PC)
}

// FDEForPC returns the Frame Description Entry for the given PC.
func (fdes FrameDescriptionEntries) FDEForPC(pc uint64) (*FrameDescriptionEntry, error) {
	idx := sort.Search(len(fdes), func(i int) bool {
		return fdes[i].Cover(pc) || fdes[i].Begin() >= pc
	})
	if idx == len(fdes) || !fdes[idx].Cover(pc) {
		return nil, &ErrNoFDEForPCError{pc}
	}
	return fdes[idx], nil
}

// Append appends otherFDEs to fdes and returns the result.
func (fdes FrameDescriptionEntries) Append(otherFDEs FrameDescriptionEntries) FrameDescriptionEntries {
	r := append(fdes, otherFDEs...) //nolint:gocritic
	sort.SliceStable(r, func(i, j int) bool {
		return r[i].Begin() < r[j].Begin()
	})
	// remove duplicates
	uniqFDEs := fdes[:0]
	for _, fde := range fdes {
		if len(uniqFDEs) > 0 {
			last := uniqFDEs[len(uniqFDEs)-1]
			if last.Begin() == fde.Begin() && last.End() == fde.End() {
				continue
			}
		}
		uniqFDEs = append(uniqFDEs, fde)
	}
	return r
}

// ptrEnc represents a pointer encoding value, used during eh_frame decoding
// to determine how pointers were encoded.
// Least significant 4 (0xf) bytes encode the size  as well as its
// signed-ness,  most significant 4 bytes (0xf0 == ptrEncFlagsMask) are flags
// describing how the value should be interpreted (absolute, relative...)
// See https://www.airs.com/blog/archives/460.
type ptrEnc uint8

const (
	// 绝对编码
	// 绝对指针地址。
	// 其大小由 32 位或 64 位地址空间决定，将是 32 位或 64 位。
	ptrEncAbs ptrEnc = 0x00 // pointer-sized unsigned integer
	// 值要被忽略
	ptrEncOmit ptrEnc = 0xff // omitted
	// 该值为无符号 LEB128
	ptrEncUleb   ptrEnc = 0x01 // ULEB128
	ptrEncUdata2 ptrEnc = 0x02 // 2 bytes
	ptrEncUdata4 ptrEnc = 0x03 // 4 bytes
	ptrEncUdata8 ptrEnc = 0x04 // 8 bytes
	ptrEncSigned ptrEnc = 0x08 // pointer-sized signed integer
	ptrEncSleb   ptrEnc = 0x09 // SLEB128
	ptrEncSdata2 ptrEnc = 0x0a // 2 bytes, signed
	ptrEncSdata4 ptrEnc = 0x0b // 4 bytes, signed
	ptrEncSdata8 ptrEnc = 0x0c // 8 bytes, signed

	ptrEncFlagsMask ptrEnc = 0xf0

	// 高位，寻址方式
	// pc is realtive
	ptrEncPCRel ptrEnc = 0x10 // value is relative to the memory address where it appears
	// value is text  relative
	ptrEncTextRel ptrEnc = 0x20 // value is relative to the address of the text section
	// data relative
	ptrEncDataRel  ptrEnc = 0x30 // value is relative to the address of the data section
	ptrEncFuncRel  ptrEnc = 0x40 // value is relative to the start of the function
	ptrEncAligned  ptrEnc = 0x50 // value should be aligned
	ptrEncIndirect ptrEnc = 0x80 // value is an address where the real value of the pointer is stored

	ptrEncSupportedFlags = ptrEncPCRel
)

// Supported returns true if this pointer encoding is supported.
func (ptrEnc ptrEnc) Supported() bool {
	if ptrEnc != ptrEncOmit {
		// 取低4位
		szenc := ptrEnc & 0x0f
		if ((szenc > ptrEncUdata8) && (szenc < ptrEncSigned)) || (szenc > ptrEncSdata8) {
			// These values aren't defined at the moment
			return false
		}
		// 只支持 pc relative
		if (ptrEnc&ptrEncFlagsMask)&^ptrEncSupportedFlags != 0 {
			// Currently only the PC relative flag is supported
			return false
		}
	}
	return true
}
