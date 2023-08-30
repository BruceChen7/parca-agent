// Package frame contains data structures and
// related functions for parsing and searching
// through Dwarf .debug_frame data.
package frame

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/parca-dev/parca-agent/internal/dwarf/util"
)

type parsefunc func(*parseContext) parsefunc

type parseContext struct {
	staticBase uint64

	buf         *bytes.Buffer
	totalLen    int
	entries     FrameDescriptionEntries
	ciemap      map[int]*CommonInformationEntry
	common      *CommonInformationEntry
	frame       *FrameDescriptionEntry
	length      uint32
	ptrSize     int
	ehFrameAddr uint64
	err         error
}

// Parse takes in data (a byte slice) and returns FrameDescriptionEntries,
// which is a slice of FrameDescriptionEntry. Each FrameDescriptionEntry
// has a pointer to CommonInformationEntry.
// If ehFrameAddr is not zero the .eh_frame format will be used, a minor variant of DWARF described at https://www.airs.com/blog/archives/460.
// The value of ehFrameAddr will be used as the address at which eh_frame will be mapped into memory.
func Parse(data []byte, order binary.ByteOrder, staticBase uint64, ptrSize int, ehFrameAddr uint64) (FrameDescriptionEntries, error) {
	var (
		buf  = bytes.NewBuffer(data)
		pctx = &parseContext{buf: buf, totalLen: len(data), entries: newFrameIndex(), staticBase: staticBase, ptrSize: ptrSize, ehFrameAddr: ehFrameAddr, ciemap: map[int]*CommonInformationEntry{}}
	)

	// 状态机器
	for fn := parselength; buf.Len() != 0; {
		fn = fn(pctx)
		if pctx.err != nil {
			return nil, pctx.err
		}
	}

	// 设置order
	for i := range pctx.entries {
		pctx.entries[i].order = order
	}

	return pctx.entries, nil
}

func (ctx *parseContext) parsingEHFrame() bool {
	return ctx.ehFrameAddr > 0
}

func (ctx *parseContext) cieEntry(cieid uint32) bool {
	if ctx.parsingEHFrame() {
		return cieid == 0x00
	}
	return cieid == 0xffffffff
}

func (ctx *parseContext) offset() int {
	return ctx.totalLen - ctx.buf.Len()
}

// .eh_frame部分是一连串的记录。
// 每条记录是一个CIE（通用信息条目）或FDE（帧描述条目）。
// 一般来说，每个对象文件有一个CIE，每个CIE都与一个FDE列表相关
// 每个FDE通常与一个函数相关联。
// CIE和FDE一起描述了如果当前指令指针在FDE覆盖的范围内，如何向调用者解压。
// [Exception Frames](https://refspecs.linuxfoundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html)
func parselength(ctx *parseContext) parsefunc {
	// 开始解释的开始地址
	start := ctx.offset()
	// 小端字节序
	// 第一个4字节是长度
	// 记录的长度。
	// 读取4个字节。如果它们不是0xffffffffff，它们就是CIE或FDE记录的长度
	err := binary.Read(ctx.buf, binary.LittleEndian, &ctx.length) // TODO(aarzilli): this does not support 64bit DWARF
	if err != nil {
		panic("Could not read from buffer")
	}

	// 是终止符，表示结束
	if ctx.length == 0 {
		// ZERO terminator
		// 开始下一个CIE
		return parselength
	}

	// 第二个4字节是CIE id
	var cieid uint32
	err = binary.Read(ctx.buf, binary.LittleEndian, &cieid)
	if err != nil {
		panic("Could not read from buffer")
	}

	ctx.length -= 4 // take off the length of the CIE id / CIE pointer.

	// CIE is Common Information Entry
	// FDE 是 Frame Descriptor Entry
	// 如果是CIE
	// 一般来说对于CIE，它一般是0
	if ctx.cieEntry(cieid) {
		ctx.common = &CommonInformationEntry{Length: ctx.length, staticBase: ctx.staticBase, CIE_id: cieid}
		// 设置CIE信息
		ctx.ciemap[start] = ctx.common
		// 下一步用来parse CIE信息
		return parseCIE
	}

	// 计算
	if ctx.ehFrameAddr > 0 {
		cieid = uint32(start - int(cieid) + 4)
	}

	// 是一个FDE
	common := ctx.ciemap[int(cieid)]

	if common == nil {
		ctx.err = fmt.Errorf("unknown CIE_id %#x at %#x", cieid, start)
	}

	ctx.frame = &FrameDescriptionEntry{Length: ctx.length, CIE: common}
	return parseFDE
}

func parseFDE(ctx *parseContext) parsefunc {
	startOff := ctx.offset()
	// 读取指定的长度
	r := ctx.buf.Next(int(ctx.length))

	reader := bytes.NewReader(r)
	num := ctx.readEncodedPtr(addrSum(ctx.ehFrameAddr+uint64(startOff), reader), reader, ctx.frame.CIE.ptrEncAddr)
	// frame 开始的地址
	ctx.frame.begin = num + ctx.staticBase

	// For the size field in .eh_frame only the size encoding portion of the
	// address pointer encoding is considered.
	// See decode_frame_entry_1 in gdb/dwarf2-frame.c.
	// For .debug_frame ptrEncAddr is always ptrEncAbs and never has flags.
	sizePtrEnc := ctx.frame.CIE.ptrEncAddr & 0x0f
	ctx.frame.size = ctx.readEncodedPtr(0, reader, sizePtrEnc)

	// Insert into the tree after setting address range begin
	// otherwise compares won't work.
	ctx.entries = append(ctx.entries, ctx.frame)

	if ctx.parsingEHFrame() && len(ctx.frame.CIE.Augmentation) > 0 {
		// If we are parsing a .eh_frame and we saw an agumentation string then we
		// need to read the augmentation data, which are encoded as a ULEB128
		// size followed by 'size' bytes.
		n, _ := util.DecodeULEB128(reader)
		_, err := reader.Seek(int64(n), io.SeekCurrent)
		if err != nil {
			panic("Could not seek")
		}
	}

	// The rest of this entry consists of the instructions
	// so we can just grab all of the data from the buffer
	// cursor to length.

	off, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		panic("Could not seek")
	}
	ctx.frame.Instructions = r[off:]
	ctx.length = 0
	// 开始下一轮
	return parselength
}

func addrSum(base uint64, buf *bytes.Reader) uint64 {
	n, _ := buf.Seek(0, io.SeekCurrent)
	return base + uint64(n)
}

// 用来parse CommonInformationEntry
func parseCIE(ctx *parseContext) parsefunc {
	// 获取CIE的数据
	data := ctx.buf.Next(int(ctx.length))
	buf := bytes.NewBuffer(data)
	// parse version
	// 第一个字节是版本
	ctx.common.Version, _ = buf.ReadByte()

	// parse augmentation
	// 以null结尾的增量字符串
	ctx.common.Augmentation, _ = util.ParseString(buf)

	if ctx.parsingEHFrame() {
		// 比较老的gcc版本才eh
		if ctx.common.Augmentation == "eh" {
			ctx.err = fmt.Errorf("unsupported 'eh' augmentation at %#x", ctx.offset())
		}
		if len(ctx.common.Augmentation) > 0 && ctx.common.Augmentation[0] != 'z' {
			ctx.err = fmt.Errorf("unsupported augmentation at %#x (does not start with 'z')", ctx.offset())
		}
	}

	// parse code alignment factor
	// 代码对齐因子，无符号的LEB128
	ctx.common.CodeAlignmentFactor, _ = util.DecodeULEB128(buf)

	// parse data alignment factor
	// 数据对齐因子，是有符号的
	ctx.common.DataAlignmentFactor, _ = util.DecodeSLEB128(buf)

	// parse return address register
	// 返回地址寄存器
	if ctx.parsingEHFrame() && ctx.common.Version == 1 {
		b, _ := buf.ReadByte()
		ctx.common.ReturnAddressRegister = uint64(b)
	} else {
		ctx.common.ReturnAddressRegister, _ = util.DecodeULEB128(buf)
	}

	ctx.common.ptrEncAddr = ptrEncAbs

	if ctx.parsingEHFrame() && len(ctx.common.Augmentation) > 0 {
		// 获取无符号LEB128的数据
		_, _ = util.DecodeULEB128(buf) // augmentation data length
		// 第一个必须是z
		for i := 1; i < len(ctx.common.Augmentation); i++ {
			switch ctx.common.Augmentation[i] {
			// 增量字符串是L
			case 'L':
				// Language Specification data area
				_, _ = buf.ReadByte() // LSDA pointer encoding, we don't support this.
			case 'R':
				// Pointer encoding, describes how begin and size fields of FDEs are encoded.
				// 获取指针编码
				b, _ := buf.ReadByte()
				// 那么下一个字节是FDE编码
				ctx.common.ptrEncAddr = ptrEnc(b)
				if !ctx.common.ptrEncAddr.Supported() {
					ctx.err = fmt.Errorf("pointer encoding not supported %#x at %#x", ctx.common.ptrEncAddr, ctx.offset())
					return nil
				}
			case 'S':
				// Signal handler invocation frame, we don't support this but there is no associated data to read.
				// 扩增字符串中的字符'S'意味着这个CIE代表一个调用信号处理程序的堆栈框架。

			case 'P':
				// Personality function encoded as a pointer encoding byte followed by
				// the pointer to the personality function encoded as specified by the
				// pointer encoding.
				// We don't support this but have to read it anyway.
				// 如果增强字符串中的下一个字符是P，则 CIE 中的下一个字节是personality function，即 DW_EH_PE_xxx 值。
				// 接着是指向人格函数的指针，使用人格
				b, _ := buf.ReadByte()
				e := ptrEnc(b) &^ ptrEncIndirect
				if !e.Supported() {
					ctx.err = fmt.Errorf("pointer encoding not supported %#x at %#x", e, ctx.offset())
					return nil
				}
				ctx.readEncodedPtr(0, buf, e)
			default:
				ctx.err = fmt.Errorf("unsupported augmentation character %c at %#x", ctx.common.Augmentation[i], ctx.offset())
				return nil
			}
		}
	}

	// parse initial instructions
	// The rest of this entry consists of the instructions
	// so we can just grab all of the data from the buffer
	// cursor to length.
	// 下一次要parse的Instructions
	// 是FDE或CIE
	ctx.common.InitialInstructions = buf.Bytes() // ctx.buf.Next(int(ctx.length))
	ctx.length = 0

	// 继续下一个section的解析
	return parselength
}

// readEncodedPtr reads a pointer from buf encoded as specified by ptrEnc.
// This function is used to read pointers from a .eh_frame section, when
// used to parse a .debug_frame section ptrEnc will always be ptrEncAbs.
// The parameter addr is the address that the current byte of 'buf' will be
// mapped to when the executable file containing the eh_frame section being
// parse is loaded in memory.
func (ctx *parseContext) readEncodedPtr(addr uint64, buf util.ByteReaderWithLen, ptrEnc ptrEnc) uint64 {
	if ptrEnc == ptrEncOmit {
		return 0
	}

	var ptr uint64

	// TODO(javierhonduco): Check for the correctness of this.
	//nolint:exhaustive
	switch ptrEnc & 0xf {
	case ptrEncAbs, ptrEncSigned:
		ptr, _ = util.ReadUintRaw(buf, binary.LittleEndian, ctx.ptrSize)
	case ptrEncUleb:
		ptr, _ = util.DecodeULEB128(buf)
	case ptrEncUdata2:
		ptr, _ = util.ReadUintRaw(buf, binary.LittleEndian, 2)
	case ptrEncSdata2:
		ptr, _ = util.ReadUintRaw(buf, binary.LittleEndian, 2)
		ptr = uint64(int16(ptr))
	case ptrEncUdata4:
		ptr, _ = util.ReadUintRaw(buf, binary.LittleEndian, 4)
	case ptrEncSdata4:
		ptr, _ = util.ReadUintRaw(buf, binary.LittleEndian, 4)
		ptr = uint64(int32(ptr))
	case ptrEncUdata8, ptrEncSdata8:
		ptr, _ = util.ReadUintRaw(buf, binary.LittleEndian, 8)
	case ptrEncSleb:
		n, _ := util.DecodeSLEB128(buf)
		ptr = uint64(n)
	}

	if ptrEnc&0xf0 == ptrEncPCRel {
		ptr += addr
	}

	return ptr
}

// DwarfEndian determines the endianness of the DWARF by using the version number field in the debug_info section
// Trick borrowed from "debug/dwarf".New().
func DwarfEndian(infoSec []byte) binary.ByteOrder {
	if len(infoSec) < 6 {
		return binary.BigEndian
	}
	x, y := infoSec[4], infoSec[5]
	switch {
	case x == 0 && y == 0:
		return binary.BigEndian
	case x == 0:
		return binary.BigEndian
	case y == 0:
		return binary.LittleEndian
	default:
		return binary.BigEndian
	}
}
