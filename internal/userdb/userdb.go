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

package userdb

import (
	"bytes"
	"context"
	_ "embed" // Embed the users.json.xz file into the binary.
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

//go:embed userdb-date.txt
var builtInDateStr string

//go:embed users.json.xz
var compressedDMRUsersDB []byte

var userDB UserDB //nolint:golint,gochecknoglobals

var (
	ErrUpdateFailed = errors.New("update failed")
	ErrUnmarshal    = errors.New("unmarshal failed")
	ErrLoading      = errors.New("error loading DMR users database")
	ErrNoUsers      = errors.New("no DMR users found in database")
	ErrParsingDate  = errors.New("error parsing built-in date")
	ErrXZReader     = errors.New("error creating xz reader")
	ErrReadDB       = errors.New("error reading database")
	ErrDecodingDB   = errors.New("error decoding DMR users database")
)

const (
	waitTime          = 100 * time.Millisecond
	defaultUsersDBURL = "https://www.radioid.net/static/users.json"
	updateTimeout     = 10 * time.Minute
	envOverrideDBURL  = "OVERRIDE_USERS_DB_URL"
)

// ---- New additions for forced network check ----

// forceUsersListCheck is set to true if the environment variable
// FORCE_USERS_LIST_CHECK is defined/non-empty.
var forceUsersListCheck = os.Getenv("FORCE_USERS_LIST_CHECK") != ""

// networkCacheDuration is how long we rely on the last successful fetch
// from the network before fetching again.
const networkCacheDuration = 5 * time.Minute

// lastNetworkCheckTime stores, atomically, the last time we successfully
// fetched from the network.
var lastNetworkCheckTime atomic.Int64 // store UnixNano

func getLastNetworkCheck() time.Time {
	nano := lastNetworkCheckTime.Load()
	if nano == 0 {
		return time.Time{}
	}
	return time.Unix(0, nano)
}

func setLastNetworkCheck(t time.Time) {
	lastNetworkCheckTime.Store(t.UnixNano())
}

// ------------------------------------------------

// getUsersDBURL checks if an override is provided via environment
// variable OVERRIDE_USERS_DB_URL. If not, returns the default URL.
func getUsersDBURL() string {
	if override := os.Getenv(envOverrideDBURL); override != "" {
		return override
	}
	return defaultUsersDBURL
}

type UserDB struct {
	uncompressedJSON   []byte
	dmrUsers           atomic.Value
	dmrUserMap         *xsync.MapOf[uint, DMRUser]
	dmrUserMapUpdating *xsync.MapOf[uint, DMRUser]

	builtInDate time.Time
	isInited    atomic.Bool
	isDone      atomic.Bool
}

type dmrUserDB struct {
	Users []DMRUser `json:"users"`
	Date  time.Time `json:"-"`
}

type DMRUser struct {
	ID       uint   `json:"id"`
	State    string `json:"state"`
	RadioID  uint   `json:"radio_id"`
	Surname  string `json:"surname"`
	City     string `json:"city"`
	Callsign string `json:"callsign"`
	Country  string `json:"country"`
	Name     string `json:"name"`
	FName    string `json:"fname"`
}

func IsValidUserID(dmrID uint) bool {
	// Check that the user id is 7 digits
	return dmrID >= 1_000_000 && dmrID <= 9_999_999
}

func ValidUserCallsign(dmrID uint, callsign string) bool {
	if !userDB.isDone.Load() {
		err := UnpackDB()
		if err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return false
		}
	}
	user, ok := userDB.dmrUserMap.Load(dmrID)
	if !ok {
		return false
	}

	if user.ID != dmrID {
		return false
	}

	return strings.EqualFold(user.Callsign, callsign)
}

func (e *dmrUserDB) Unmarshal(b []byte) error {
	if err := json.Unmarshal(b, e); err != nil {
		return ErrUnmarshal
	}
	return nil
}

// UnpackDB initializes or re-initializes the in-memory user database.
//
// If FORCE_USERS_LIST_CHECK is set, the built-in data is ignored completely,
// and only the network-updated data is used, with a 5-minute cache in RAM.
func UnpackDB() error {
	// 1) If forced check is set, skip built-in data and rely on the network (cached for 5 minutes).
	if forceUsersListCheck {
		lastCheck := getLastNetworkCheck()
		if time.Since(lastCheck) > networkCacheDuration {
			logging.Log("FORCE_USERS_LIST_CHECK is set; updating from network only.")
			if err := Update(); err != nil {
				logging.Errorf("Forced network update failed: %v", err)
				// No fallback to local data; we must rely on the network if forced.
				return err
			}
			setLastNetworkCheck(time.Now())
		}

		// Mark userDB as "done" if not already done, so subsequent calls skip initialization.
		if !userDB.isInited.Load() {
			userDB.isInited.Store(true)
		}
		if !userDB.isDone.Load() {
			userDB.isDone.Store(true)
		}

		// Ensure there's data
		usrdb, ok := userDB.dmrUsers.Load().(dmrUserDB)
		if !ok || len(usrdb.Users) == 0 {
			return ErrNoUsers
		}
		return nil
	}

	// 2) Otherwise do the original embedded/built-in data unpack logic.
	lastInit := userDB.isInited.Swap(true)
	if !lastInit {
		userDB.dmrUserMap = xsync.NewMapOf[uint, DMRUser]()
		userDB.dmrUserMapUpdating = xsync.NewMapOf[uint, DMRUser]()

		var err error
		userDB.builtInDate, err = time.Parse(time.RFC3339, builtInDateStr)
		if err != nil {
			return ErrParsingDate
		}

		dbReader, err := xz.NewReader(bytes.NewReader(compressedDMRUsersDB))
		if err != nil {
			return ErrXZReader
		}
		userDB.uncompressedJSON, err = io.ReadAll(dbReader)
		if err != nil {
			return ErrReadDB
		}

		var tmpDB dmrUserDB
		if err := json.Unmarshal(userDB.uncompressedJSON, &tmpDB); err != nil {
			return ErrDecodingDB
		}
		tmpDB.Date = userDB.builtInDate
		userDB.dmrUsers.Store(tmpDB)

		// Load all into map
		for i := range tmpDB.Users {
			userDB.dmrUserMapUpdating.Store(tmpDB.Users[i].ID, tmpDB.Users[i])
		}
		userDB.dmrUserMap = userDB.dmrUserMapUpdating
		userDB.dmrUserMapUpdating = xsync.NewMapOf[uint, DMRUser]()
		userDB.isDone.Store(true)
	}

	// Wait if needed for any in-progress initialization
	for !userDB.isDone.Load() {
		time.Sleep(waitTime)
	}

	usrdb, ok := userDB.dmrUsers.Load().(dmrUserDB)
	if !ok {
		logging.Error("Error loading DMR users database")
		return ErrLoading
	}
	if len(usrdb.Users) == 0 {
		logging.Error("No DMR users found in database")
		return ErrNoUsers
	}
	return nil
}

func Len() int {
	if !userDB.isDone.Load() {
		if err := UnpackDB(); err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return 0
		}
	}
	db, ok := userDB.dmrUsers.Load().(dmrUserDB)
	if !ok {
		logging.Error("Error loading DMR users database")
	}
	return len(db.Users)
}

func Get(dmrID uint) (DMRUser, bool) {
	if !userDB.isDone.Load() {
		if err := UnpackDB(); err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return DMRUser{}, false
		}
	}
	user, ok := userDB.dmrUserMap.Load(dmrID)
	if !ok {
		return DMRUser{}, false
	}
	return user, true
}

// Update explicitly fetches the user data from the network.
//
// If FORCE_USERS_LIST_CHECK is set, UnpackDB() may call Update() automatically
// every 5 minutes. Otherwise, you can call it manually when you wish to refresh.
func Update() error {
	if !userDB.isDone.Load() {
		if err := UnpackDB(); err != nil {
			logging.Errorf("Error unpacking database: %v", err)
			return ErrUpdateFailed
		}
	}

	// Use helper to possibly override with env variable
	url := getUsersDBURL()

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
		if cerr := resp.Body.Close(); cerr != nil {
			logging.Errorf("Error closing response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return ErrUpdateFailed
	}

	userDB.uncompressedJSON, err = io.ReadAll(resp.Body)
	if err != nil {
		logging.Errorf("ReadAll error %s", err)
		return ErrUpdateFailed
	}

	var tmpDB dmrUserDB
	if err := json.Unmarshal(userDB.uncompressedJSON, &tmpDB); err != nil {
		logging.Errorf("Error decoding DMR users database: %v", err)
		return ErrUpdateFailed
	}

	if len(tmpDB.Users) == 0 {
		logging.Error("No DMR users found in database")
		return ErrUpdateFailed
	}

	tmpDB.Date = time.Now()
	userDB.dmrUsers.Store(tmpDB)

	userDB.dmrUserMapUpdating = xsync.NewMapOf[uint, DMRUser]()
	for i := range tmpDB.Users {
		userDB.dmrUserMapUpdating.Store(tmpDB.Users[i].ID, tmpDB.Users[i])
	}

	userDB.dmrUserMap = userDB.dmrUserMapUpdating
	userDB.dmrUserMapUpdating = xsync.NewMapOf[uint, DMRUser]()

	logging.Log("Update complete")
	return nil
}

func GetDate() (time.Time, error) {
	if !userDB.isDone.Load() {
		if err := UnpackDB(); err != nil {
			return time.Time{}, err
		}
	}
	db, ok := userDB.dmrUsers.Load().(dmrUserDB)
	if !ok {
		logging.Error("Error loading DMR users database")
		return time.Time{}, ErrLoading
	}
	return db.Date, nil
}
