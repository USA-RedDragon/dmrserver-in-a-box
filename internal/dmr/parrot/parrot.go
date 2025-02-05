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

package parrot

import (
	"context"

	"github.com/USA-RedDragon/DMRHub/internal/db/models"
	"github.com/USA-RedDragon/DMRHub/internal/logging"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
)

// Parrot is a struct that stores packets and repeats them back to the repeater.
type Parrot struct {
	Redis redisParrotStorage
}

// NewParrot creates a new parrot instance.
func NewParrot(redis *redis.Client) *Parrot {
	return &Parrot{
		Redis: makeRedisParrotStorage(redis),
	}
}

// IsStarted returns true if the stream is already started.
func (p *Parrot) IsStarted(ctx context.Context, streamID uint) bool {
	return p.Redis.exists(ctx, streamID)
}

// StartStream starts a new stream.
func (p *Parrot) StartStream(ctx context.Context, streamID uint, repeaterID uint) bool {
	ctx, span := otel.Tracer("DMRHub").Start(ctx, "Parrot.StartStream")
	defer span.End()

	if !p.Redis.exists(ctx, streamID) {
		p.Redis.store(ctx, streamID, repeaterID)
		return true
	}
	logging.Errorf("Parrot: Stream %d already started", streamID)
	return false
}

// RecordPacket records a packet from the stream.
func (p *Parrot) RecordPacket(ctx context.Context, streamID uint, packet models.Packet) {
	ctx, span := otel.Tracer("DMRHub").Start(ctx, "Parrot.RecordPacket")
	defer span.End()

	go p.Redis.refresh(ctx, streamID)

	// Grab the repeater ID to go ahead and mark the packet as being routed back.
	repeaterID, err := p.Redis.get(ctx, streamID)
	if err != nil {
		logging.Errorf("Error getting parrot stream from redis: %v", err)
		return
	}

	packet.Repeater = repeaterID
	packet.Src, packet.Dst = packet.Dst, packet.Src
	packet.GroupCall = false

	err = p.Redis.stream(ctx, streamID, packet)
	if err != nil {
		logging.Errorf("Error storing parrot stream in redis: %v", err)
	}
}

// StopStream stops a stream.
func (p *Parrot) StopStream(ctx context.Context, streamID uint) {
	ctx, span := otel.Tracer("DMRHub").Start(ctx, "Parrot.StopStream")
	defer span.End()

	p.Redis.delete(ctx, streamID)
}

// GetStream returns the stream.
func (p *Parrot) GetStream(ctx context.Context, streamID uint) []models.Packet {
	ctx, span := otel.Tracer("DMRHub").Start(ctx, "Parrot.GetStream")
	defer span.End()

	// Empty array of packet byte arrays.
	packets, err := p.Redis.getStream(ctx, streamID)
	if err != nil {
		logging.Errorf("Error getting parrot stream from redis: %s", err)
		return nil
	}

	return packets
}
