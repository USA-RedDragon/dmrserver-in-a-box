// SPDX-License-Identifier: AGPL-3.0-or-later
// DMRHub - Run a DMR network server in a single binary
// Copyright (C) 2023-2024 Jacob McSwain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
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

package repeaterdb

import (
	"bytes"
	"context"
	_ "embed" // Embed the repeaters.json.xz file into the binary.
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/USA-RedDragon/DMRHub/internal/logging"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/ulikunitz/xz"
)

//go:embed repeaterdb-date.txt
var builtInDateStr string

//go:embed repeaters.json.xz
var comressedDMRRepeatersDB []byte

var repeaterDB RepeaterDB //nolint:golint,gochecknoglobals

var (
	ErrUpdateFailed = errors.New("update failed")
	ErrUnmarshal    = errors.New("unmarshal failed")
	ErrLoading      = errors.New("error loading DMR users database")
	ErrNoRepeaters  = errors.New("no DMR repeaters found in database")
	ErrParsingDate  = errors.New("error parsing built-in date")
	ErrXZReader     = errors.New("error creating xz reader")
	ErrReadDB       = errors.New("error reading database")
	ErrDecodingDB   = errors.New("error decoding DMR repeaters database")
)

const (
	waitTime                  = 100 * time.Millisecond
	defaultRepeatersDBURL     = "https://www.radioid.net/static/rptrs.json"
	envOverrideRepeatersDBURL = "OVERRIDE_REPEATERS_DB_URL"
	updateTimeout             = 10 * time.Minute
)

// --- New additions below:

// forceRepeaterListCheck indicates whether we *only* check the network-updated
// list (ignoring the embedded or previously loaded local data).
var forceRepeaterListCheck = os.Getenv("FORCE_REPEATER_LIST_CHECK") != ""

// networkCacheDuration is how long (in minutes) we rely on the cached
// network data before fetching again.
const networkCacheDuration = 5 * time.Minute

// lastNetworkCheckTime is the last time we successfully updated from the network.
var lastNetworkCheckTime atomic.Int64 // store UnixNano time

func getLastNetworkCheck() time.Time {
	unixNano := lastNetworkCheckTime.Load()
	if unixNano == 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano)
}

func setLastNetworkCheck(t time.Time) {
	lastNetworkCheckTime.Store(t.UnixNano())
}

// --- End new additions ---

// getRepeatersDBURL checks if an override is provided via environment
// variable OVERRIDE_REPEATERS_DB_URL. If not, returns the default URL.
func getRepeatersDBURL() string {
	if override := os.Getenv(envOverrideRepeatersDBURL); override != "" {
		return override
	}
	return defaultRepeatersDBURL
}

type RepeaterDB struct {
	uncompressedJSON       []byte
	dmrRepeaters           atomic.Value
	dmrRepeaterMap         *xsync.MapOf[uint, DMRRepeater]
	dmrRepeaterMapUpdating *xsync.MapOf[uint, DMRRepeater]

	builtInDate time.Time
	isInited    atomic.Bool
	isDone      atomic.Bool
}

type dmrRepeaterDB struct {
	Repeaters []DMRRepeater `json:"rptrs"`
	Date      time.Time     `json:"-"`
}

type DMRRepeater struct {
	Locator     uint   `json:"locator"`
	ID          uint   `json:"id"`
	Callsign    string `json:"callsign"`
	City        string `json:"city"`
	State       string `json:"state"`
	Country     string `json:"country"`
	Frequency   string `json:"frequency"`
	ColorCode   uint   `json:"color_code"`
	Offset      string `json:"offset"`
	Assigned    string `json:"assigned"`
	TSLinked    string `json:"ts_linked"`
	Trustee     string `json:"trustee"`
	MapInfo     string `json:"map_info"`
	Map         uint   `json:"map"`
	IPSCNetwork string `json:"ipsc_network"`
}

func IsValidRepeaterID(dmrID uint) bool {
	// Check that the repeater id is 6 digits
	return dmrID >= 100000 && dmrID <= 999999
}

func ValidRepeaterCallsign(dmrID uint, callsign string) bool {
	if !repeaterDB.isDone.Load() {
		err := UnpackDB()
		if err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return false
		}
	}

	repeater, ok := repeaterDB.dmrRepeaterMap.Load(dmrID)
	if !ok {
		return false
	}

	return strings.EqualFold(repeater.Trustee, callsign)
}

func (e *dmrRepeaterDB) Unmarshal(b []byte) error {
	err := json.Unmarshal(b, e)
	if err != nil {
		return ErrUnmarshal
	}
	return nil
}

// UnpackDB is responsible for ensuring the internal repeaterDB is initialized.
//
// If FORCE_REPEATER_LIST_CHECK is set:
//   - We ignore the built-in data and rely solely on the network-updated data.
//   - We only perform an HTTP fetch if 5 minutes (networkCacheDuration) have
//     passed since the last successful update. Otherwise, we use the in-RAM
//     cached data from the last network update.
//
// If FORCE_REPEATER_LIST_CHECK is not set:
//   - We do the usual embedded data unpack and fallback, and only call Update()
//     when you explicitly do so or at first initialization.
func UnpackDB() error {
	// 1. If forceRepeaterListCheck is set, skip the embedded/built-in data
	//    and only rely on the network database (cached for 5 minutes).
	if forceRepeaterListCheck {
		lastCheck := getLastNetworkCheck()
		if time.Since(lastCheck) > networkCacheDuration {
			logging.Log("FORCE_REPEATER_LIST_CHECK is set; checking network for repeater DB update")
			err := Update()
			if err != nil {
				// If we fail here, we do NOT fallback to local data. We simply return the error.
				logging.Errorf("Forced network update failed: %v", err)
				return err
			}
			setLastNetworkCheck(time.Now())
		}

		// Mark as initialized/done if not set yet.
		if !repeaterDB.isInited.Load() {
			repeaterDB.isInited.Store(true)
		}
		if !repeaterDB.isDone.Load() {
			repeaterDB.isDone.Store(true)
		}

		// Verify we have data
		rptdb, ok := repeaterDB.dmrRepeaters.Load().(dmrRepeaterDB)
		if !ok || len(rptdb.Repeaters) == 0 {
			return ErrNoRepeaters
		}
		return nil
	}

	// 2. If we are not forcing network check, do the original built-in
	//    data unpack logic (the normal flow).
	lastInit := repeaterDB.isInited.Swap(true)
	if !lastInit {
		// First-time init from embedded data
		repeaterDB.dmrRepeaterMap = xsync.NewMapOf[uint, DMRRepeater]()
		repeaterDB.dmrRepeaterMapUpdating = xsync.NewMapOf[uint, DMRRepeater]()

		var err error
		repeaterDB.builtInDate, err = time.Parse(time.RFC3339, builtInDateStr)
		if err != nil {
			return ErrParsingDate
		}
		dbReader, err := xz.NewReader(bytes.NewReader(comressedDMRRepeatersDB))
		if err != nil {
			return ErrXZReader
		}
		repeaterDB.uncompressedJSON, err = io.ReadAll(dbReader)
		if err != nil {
			return ErrReadDB
		}
		var tmpDB dmrRepeaterDB
		if err := json.Unmarshal(repeaterDB.uncompressedJSON, &tmpDB); err != nil {
			return ErrDecodingDB
		}

		tmpDB.Date = repeaterDB.builtInDate
		repeaterDB.dmrRepeaters.Store(tmpDB)
		for i := range tmpDB.Repeaters {
			repeaterDB.dmrRepeaterMapUpdating.Store(tmpDB.Repeaters[i].ID, tmpDB.Repeaters[i])
		}

		repeaterDB.dmrRepeaterMap = repeaterDB.dmrRepeaterMapUpdating
		repeaterDB.dmrRepeaterMapUpdating = xsync.NewMapOf[uint, DMRRepeater]()
		repeaterDB.isDone.Store(true)
	}

	// Wait for any in-progress initialization to complete
	for !repeaterDB.isDone.Load() {
		time.Sleep(waitTime)
	}

	rptdb, ok := repeaterDB.dmrRepeaters.Load().(dmrRepeaterDB)
	if !ok {
		return ErrLoading
	}
	if len(rptdb.Repeaters) == 0 {
		return ErrNoRepeaters
	}
	return nil
}

func Len() int {
	if !repeaterDB.isDone.Load() {
		err := UnpackDB()
		if err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return 0
		}
	}
	db, ok := repeaterDB.dmrRepeaters.Load().(dmrRepeaterDB)
	if !ok {
		logging.Error("Error loading DMR users database")
	}
	return len(db.Repeaters)
}

func Get(id uint) (DMRRepeater, bool) {
	if !repeaterDB.isDone.Load() {
		err := UnpackDB()
		if err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return DMRRepeater{}, false
		}
	}
	repeater, ok := repeaterDB.dmrRepeaterMap.Load(id)
	if !ok {
		return DMRRepeater{}, false
	}
	return repeater, true
}

// Update explicitly fetches the repeater data from the network.
//
// If FORCE_REPEATER_LIST_CHECK is set, UnpackDB() will call Update() automatically
// every 5 minutes, ignoring the built-in data. If it's *not* set, you can call
// Update() manually to refresh.
func Update() error {
	if !repeaterDB.isDone.Load() {
		err := UnpackDB()
		if err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return ErrUpdateFailed
		}
	}

	// Use the helper to get the URL from an environment variable,
	// falling back to the default if not set.
	url := getRepeatersDBURL()

	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ErrUpdateFailed
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ErrUpdateFailed
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return ErrUpdateFailed
	}

	repeaterDB.uncompressedJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		return ErrUpdateFailed
	}

	var tmpDB dmrRepeaterDB
	if err := json.Unmarshal(repeaterDB.uncompressedJSON, &tmpDB); err != nil {
		logging.Errorf("Error decoding DMR repeaters database: %v", err)
		return ErrUpdateFailed
	}

	if len(tmpDB.Repeaters) == 0 {
		logging.Error("No DMR repeaters found in database")
		return ErrUpdateFailed
	}

	tmpDB.Date = time.Now()
	repeaterDB.dmrRepeaters.Store(tmpDB)

	repeaterDB.dmrRepeaterMapUpdating = xsync.NewMapOf[uint, DMRRepeater]()
	for i := range tmpDB.Repeaters {
		repeaterDB.dmrRepeaterMapUpdating.Store(tmpDB.Repeaters[i].ID, tmpDB.Repeaters[i])
	}

	repeaterDB.dmrRepeaterMap = repeaterDB.dmrRepeaterMapUpdating
	repeaterDB.dmrRepeaterMapUpdating = xsync.NewMapOf[uint, DMRRepeater]()

	logging.Log("Update complete")
	return nil
}

func GetDate() (time.Time, error) {
	if !repeaterDB.isDone.Load() {
		err := UnpackDB()
		if err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return time.Time{}, err
		}
	}
	db, ok := repeaterDB.dmrRepeaters.Load().(dmrRepeaterDB)
	if !ok {
		logging.Error("Error loading DMR users database")
	}
	return db.Date, nil
}
