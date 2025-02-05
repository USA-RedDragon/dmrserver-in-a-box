// SPDX-License-Identifier: AGPL-3.0-or-later
// DMRHub - Run a DMR network server in a single binary
// Copyright (C) 2023-2024 Jacob McSwain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// The source code is available at <https://github.com/USA-RedDragon/DMRHub>

package models

import (
	"fmt"

	"github.com/USA-RedDragon/DMRHub/internal/dmr/dmrconst"
)

// Packet is a DMR packet
//
//go:generate go run github.com/tinylib/msgp
type Packet struct {
	Signature   string             `msg:"signature"`
	Seq         uint               `msg:"seq"`
	Src         uint               `msg:"src"`
	Dst         uint               `msg:"dst"`
	Repeater    uint               `msg:"repeater"`
	Slot        bool               `msg:"slot"`
	GroupCall   bool               `msg:"groupCall"`
	FrameType   dmrconst.FrameType `msg:"frameType,extension"`
	DTypeOrVSeq uint               `msg:"dtypeOrVSeq"`
	StreamID    uint               `msg:"streamID"`
	DMRData     [33]byte           `msg:"dmrData"`
	// The next two are technically unsigned, but the data type is 1 byte
	// We also want to be able to represent -1 as a null, so we use int
	BER  int `msg:"ber"`
	RSSI int `msg:"rssi"`
}

func (p Packet) Equal(other Packet) bool {
	if p.Signature != other.Signature {
		return false
	}
	if p.Seq != other.Seq {
		return false
	}
	if p.Src != other.Src {
		return false
	}
	if p.Dst != other.Dst {
		return false
	}
	if p.Repeater != other.Repeater {
		return false
	}
	if p.Slot != other.Slot {
		return false
	}
	if p.GroupCall != other.GroupCall {
		return false
	}
	if p.FrameType != other.FrameType {
		return false
	}
	if p.DTypeOrVSeq != other.DTypeOrVSeq {
		return false
	}
	if p.StreamID != other.StreamID {
		return false
	}
	if p.DMRData != other.DMRData {
		return false
	}
	if p.BER != other.BER {
		return false
	}
	if p.RSSI != other.RSSI {
		return false
	}
	return true
}

func UnpackPacket(data []byte) (Packet, bool) {
	var packet Packet
	if len(data) < dmrconst.HBRPPacketLength {
		return packet, false
	}
	if len(data) > dmrconst.HBRPMaxPacketLength {
		return packet, false
	}
	packet.Signature = string(data[:4])
	packet.Seq = uint(data[4])
	packet.Src = uint(data[5])<<16 | uint(data[6])<<8 | uint(data[7])
	packet.Dst = uint(data[8])<<16 | uint(data[9])<<8 | uint(data[10])
	packet.Repeater = uint(data[11])<<24 | uint(data[12])<<16 | uint(data[13])<<8 | uint(data[14])
	bits := data[15]
	packet.Slot = false
	if (bits & 0x80) != 0 { //nolint:golint,gomnd
		packet.Slot = true
	}
	packet.GroupCall = true
	if (bits & 0x40) != 0 { //nolint:golint,gomnd
		packet.GroupCall = false
	}
	packet.FrameType = dmrconst.FrameType((bits & 0x30) >> 4) //nolint:golint,gomnd
	packet.DTypeOrVSeq = uint(bits & 0xF)                     //nolint:golint,gomnd
	packet.StreamID = uint(data[16])<<24 | uint(data[17])<<16 | uint(data[18])<<8 | uint(data[19])
	copy(packet.DMRData[:], data[20:53])

	// Bytes 53-54 are BER and RSSI, respectively
	// But they are optional, so don't error if they don't exist

	// Rui Barreiros - 2024/12/12
	// As per comment in Encode() these should be set (even if optional)
	// so it doesn't break other (arguably) not well made software
	// in hindsight, the data field could be changed to uint, but then we
	// would need to change alot, exercise for future.
	if len(data) > dmrconst.HBRPPacketLength {
		packet.BER = int(data[dmrconst.HBRPPacketLength])
	} else {
		packet.BER = 0
	}
	
	if len(data) > dmrconst.HBRPPacketLength+1 {
		packet.RSSI = int(data[dmrconst.HBRPPacketLength+1])
	} else {
		packet.RSSI = 0
	}
	
	return packet, true
}

func (p *Packet) String() string {
	return fmt.Sprintf(
		"Packet: Seq %d, Src %d, Dst %d, Repeater %d, Slot %t, GroupCall %t, FrameType=%s, DTypeOrVSeq %d, StreamId %d, BER %d, RSSI %d, DMRData %v",
		p.Seq, p.Src, p.Dst, p.Repeater, p.Slot, p.GroupCall, p.FrameType.String(), p.DTypeOrVSeq, p.StreamID, p.BER, p.RSSI, p.DMRData,
	)
}

func (p *Packet) Encode() []byte {
	// Encode the packet as we decoded
	data := make([]byte, dmrconst.HBRPPacketLength)
	copy(data[:4], []byte(p.Signature))
	data[4] = byte(p.Seq)
	data[5] = byte(p.Src >> 16) //nolint:golint,gomnd
	data[6] = byte(p.Src >> 8)  //nolint:golint,gomnd
	data[7] = byte(p.Src)
	data[8] = byte(p.Dst >> 16) //nolint:golint,gomnd
	data[9] = byte(p.Dst >> 8)  //nolint:golint,gomnd
	data[10] = byte(p.Dst)
	data[11] = byte(p.Repeater >> 24) //nolint:golint,gomnd
	data[12] = byte(p.Repeater >> 16) //nolint:golint,gomnd
	data[13] = byte(p.Repeater >> 8)  //nolint:golint,gomnd
	data[14] = byte(p.Repeater)
	bits := byte(0)
	if p.Slot {
		bits |= 0x80
	}
	if !p.GroupCall {
		bits |= 0x40
	}
	bits |= byte(p.FrameType << 4) //nolint:golint,gomnd
	bits |= byte(p.DTypeOrVSeq)
	data[15] = bits
	data[16] = byte(p.StreamID >> 24) //nolint:golint,gomnd
	data[17] = byte(p.StreamID >> 16) //nolint:golint,gomnd
	data[18] = byte(p.StreamID >> 8)  //nolint:golint,gomnd
	data[19] = byte(p.StreamID)
	copy(data[20:53], p.DMRData[:])

	// Rui Barreiros - 2024/12/12
	// From what I understand, most applications expect BER and RSSI
	// and some (wrongly) do a packet size check, taking these 2 into
	// account, therefore, it's better to always add them, at 0 if
	// they are not set.
	
	// If BER and RSSI are set, add them else add and set them at 0
	if p.BER != -1 && p.RSSI != -1 {
		p.BER = 0
		p.RSSI = 0
	}

	data = append(data, byte(p.BER))
	data = append(data, byte(p.RSSI))

	return data
}
