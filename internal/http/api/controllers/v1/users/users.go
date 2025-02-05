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

package users

import (
	"crypto/sha1" //#nosec G505 -- False positive, we are not using this for crypto, just HIBP
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/USA-RedDragon/DMRHub/internal/config"
	"github.com/USA-RedDragon/DMRHub/internal/db/models"
	"github.com/USA-RedDragon/DMRHub/internal/dmr/dmrconst"
	"github.com/USA-RedDragon/DMRHub/internal/http/api/apimodels"
	"github.com/USA-RedDragon/DMRHub/internal/http/api/utils"
	"github.com/USA-RedDragon/DMRHub/internal/logging"
	"github.com/USA-RedDragon/DMRHub/internal/smtp"
	"github.com/USA-RedDragon/DMRHub/internal/userdb"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	gopwned "github.com/mavjs/goPwned"
	"gorm.io/gorm"
)

func GETUsers(c *gin.Context) {
	db, ok := c.MustGet("PaginatedDB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	cDb, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	users, err := models.ListUsers(db)
	if err != nil {
		logging.Errorf("GETUsers: Error getting users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting users"})
		return
	}

	total, err := models.CountUsers(cDb)
	if err != nil {
		logging.Errorf("GETUsers: Error getting user count: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user count"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "users": users})
}

// POSTUser is used to register a new user.
func POSTUser(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	var json apimodels.UserRegistration
	err := c.ShouldBindJSON(&json)
	if err != nil {
		logging.Errorf("POSTUser: JSON data is invalid: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON data is invalid"})
	} else {
		if config.GetConfig().EnforceRadioid {
			if !userdb.IsValidUserID(json.DMRId) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "DMR ID is not valid"})
				return
			}

			if !userdb.ValidUserCallsign(json.DMRId, json.Callsign) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Callsign does not match DMR ID"})
				return
			}
		}
		
		isValid, errString := json.IsValidUsername()
		if !isValid {
			c.JSON(http.StatusBadRequest, gin.H{"error": errString})
			return
		}

		// Check that password isn't a zero string
		if json.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password cannot be blank"})
			return
		}

		// Check if the username is already taken
		var user models.User
		err := db.Find(&user, "username = ?", json.Username).Error
		if err != nil {
			logging.Errorf("POSTUser: Error getting user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user"})
			return
		} else if user.ID != 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username is already taken"})
			return
		}

		// Check if the DMR ID is already taken
		exists, err := models.UserIDExists(db, json.DMRId)
		if err != nil {
			logging.Errorf("POSTUser: Error getting user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user"})
			return
		}
		if exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "DMR ID is already registered"})
			return
		}

		if config.GetConfig().HIBPAPIKey != "" {
			goPwned := gopwned.NewClient(nil, config.GetConfig().HIBPAPIKey)
			h := sha1.New() //#nosec G401 -- False positive, we are not using this for crypto, just HIBP
			h.Write([]byte(json.Password))
			sha1HashedPW := fmt.Sprintf("%X", h.Sum(nil))
			frange := sha1HashedPW[0:5]
			lrange := sha1HashedPW[5:40]
			karray, err := goPwned.GetPwnedPasswords(frange, false)
			if err != nil {
				// If the error message starts with "Too many requests", then tell the user to retry in one minute
				if strings.HasPrefix(err.Error(), "Too many requests") {
					c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests. Please try again in one minute"})
					return
				}
				logging.Errorf("POSTUser: Error getting pwned passwords: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting pwned passwords"})
				return
			}
			strKArray := string(karray)
			respArray := strings.Split(strKArray, "\r\n")

			var result int64
			for _, resp := range respArray {
				strArray := strings.Split(resp, ":")
				test := strArray[0]

				count, err := strconv.ParseInt(strArray[1], 0, 32)
				if err != nil {
					logging.Errorf("POSTUser: Error parsing pwned password count: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Error parsing pwned password count"})
					return
				}
				if test == lrange {
					result = count
				}
			}
			if result > 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Password has been reported in a data breach. Please use another one"})
				return
			}
		}

		// argon2 the password
		hashedPassword := utils.HashPassword(json.Password, config.GetConfig().PasswordSalt)

		// store the user in the database with Active = false
		user = models.User{
			Username: json.Username,
			Password: hashedPassword,
			Callsign: strings.ToUpper(json.Callsign),
			ID:       json.DMRId,
			Approved: false,
			Admin:    false,
		}
		err = db.Create(&user).Error
		if err != nil {
			logging.Errorf("POSTUser: Error creating user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "User created, please wait for admin approval"})
		if config.GetConfig().EnableEmail {
			err := smtp.Send(
				config.GetConfig().AdminEmail,
				"New user registration",
				fmt.Sprintf("A new user has registered.<br><br>Username: %s<br>Callsign: %s<br>DMR ID: %d<br><br><a href=\"%s/admin/users/approval\">Click here</a> to see the approval dashboard", json.Username, strings.ToUpper(json.Callsign), json.DMRId, config.GetConfig().CanonicalHost),
			)
			if err != nil {
				logging.Errorf("POSTUser: Error sending email: %v", err)
			}
		}
	}
}

func POSTUserDemote(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	id := c.Param("id")

	userID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}
	session := sessions.Default(c)
	fromUserID, ok := session.Get("user_id").(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}
	if uint(userID) == fromUserID {
		// don't allow a user to demote themselves
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot demote yourself"})
		return
	}
	// Grab the user from the database
	user, err := models.FindUserByID(db, uint(userID))
	if err != nil {
		logging.Errorf("POSTUserDemote: Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user"})
		return
	}

	user.Admin = false
	err = db.Save(&user).Error
	if err != nil {
		logging.Errorf("POSTUserDemote: Error saving user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User demoted"})

	if config.GetConfig().EnableEmail {
		err := smtp.Send(
			config.GetConfig().AdminEmail,
			"Admin user demotion",
			fmt.Sprintf("An admin has been demoted.<br><br>Username: %s<br>Callsign: %s<br>DMR ID: %d", user.Username, strings.ToUpper(user.Callsign), user.ID),
		)
		if err != nil {
			logging.Errorf("POSTUserDemote: Error sending email: %v", err)
		}
	}
}

func POSTUserPromote(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	id := c.Param("id")
	idInt, err := strconv.Atoi(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}

	// Grab the user from the database
	user, err := models.FindUserByID(db, uint(idInt))
	if err != nil {
		logging.Errorf("POSTUserPromote: Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user"})
		return
	}
	if user.ID == dmrconst.ParrotUser {
		// Prevent promoting the Parrot user
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot promote the Parrot user"})
		return
	}
	if !user.Approved {
		// Prevent promoting an unapproved user
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot promote an unapproved user"})
		return
	}
	user.Admin = true
	err = db.Save(&user).Error
	if err != nil {
		logging.Errorf("POSTUserPromote: Error saving user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User promoted"})

	if config.GetConfig().EnableEmail {
		err := smtp.Send(
			config.GetConfig().AdminEmail,
			"Admin user promotion",
			fmt.Sprintf("An admin has been promoted.<br><br>Username: %s<br>Callsign: %s<br>DMR ID: %d", user.Username, strings.ToUpper(user.Callsign), user.ID),
		)
		if err != nil {
			logging.Errorf("POSTUserPromote: Error sending email: %v", err)
		}
	}
}

func POSTUserUnsuspend(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	id := c.Param("id")

	userID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}
	session := sessions.Default(c)
	fromUserID, ok := session.Get("user_id").(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}
	if uint(userID) == fromUserID {
		// don't allow a user to demote themselves
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot unsuspend yourself"})
		return
	}

	// Grab the user from the database
	user, err := models.FindUserByID(db, uint(userID))
	if err != nil {
		logging.Errorf("POSTUserUnsuspend: Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user"})
		return
	}

	user.Suspended = false
	err = db.Save(&user).Error
	if err != nil {
		logging.Errorf("POSTUserUnsuspend: Error saving user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User unsuspended"})
}

func POSTUserApprove(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	id := c.Param("id")

	userID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}
	session := sessions.Default(c)
	fromUserID, ok := session.Get("user_id").(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not logged in"})
		return
	}
	if uint(userID) == fromUserID {
		// don't allow a user to demote themselves
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot approve yourself"})
		return
	}

	// Grab the user from the database
	user, err := models.FindUserByID(db, uint(userID))
	if err != nil {
		logging.Errorf("POSTUserApprove: Error getting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user"})
		return
	}

	user.Approved = true
	err = db.Save(&user).Error
	if err != nil {
		logging.Errorf("POSTUserApprove: Error saving user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User approved"})
}

func GETUser(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	id := c.Param("id")
	// Convert string id into uint
	userID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}
	user, err := models.FindUserByID(db, uint(userID))
	if err != nil {
		logging.Errorf("Error finding user: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "User does not exist"})
	}
	c.JSON(http.StatusOK, user)
}

func GETUserAdmins(c *gin.Context) {
	db, ok := c.MustGet("PaginatedDB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	cDb, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}

	users, err := models.FindUserAdmins(db)
	if err != nil {
		logging.Errorf("Error finding users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Admins not found"})
		return
	}

	total, err := models.CountUserAdmins(cDb)
	if err != nil {
		logging.Errorf("Error counting users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Admins not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users, "total": total})
}

func GETUserSuspended(c *gin.Context) {
	db, ok := c.MustGet("PaginatedDB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	cDb, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	// Get all users where approved = false
	users, err := models.FindUserSuspended(db)
	if err != nil {
		logging.Errorf("Error finding users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Suspended users not found"})
		return
	}
	total, err := models.CountUserSuspended(cDb)
	if err != nil {
		logging.Errorf("Error counting users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Suspended users not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users, "total": total})
}

func GETUserUnapproved(c *gin.Context) {
	db, ok := c.MustGet("PaginatedDB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	cDb, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	// Get all users where approved = false
	users, err := models.FindUserUnapproved(db)
	if err != nil {
		logging.Errorf("Error finding users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unapproved users not found"})
		return
	}

	total, err := models.CountUserUnapproved(cDb)
	if err != nil {
		logging.Errorf("Error counting users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unapproved users not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users, "total": total})
}

func PATCHUser(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	id := c.Param("id")
	idInt, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}
	var json apimodels.UserPatch
	err = c.ShouldBindJSON(&json)
	if err != nil {
		logging.Errorf("PATCHUser: JSON data is invalid: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON data is invalid"})
	} else {
		user, err := models.FindUserByID(db, uint(idInt))
		if err != nil {
			logging.Errorf("Error finding user: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "User does not exist"})
			return
		}

		if json.Callsign != "" {
			// Check DMR ID is in the database
			if userdb.ValidUserCallsign(user.ID, json.Callsign) {
				user.Callsign = strings.ToUpper(json.Callsign)
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Callsign does not match DMR ID"})
				return
			}
		}

		if json.Username != "" {
			// Check if the username is already taken
			var existingUser models.User
			err := db.Find(&existingUser, "username = ?", json.Username).Error
			if err != nil {
				logging.Errorf("Error finding user: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error finding user"})
				return
			} else if existingUser.ID != 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Username is already taken"})
				return
			}
			user.Username = json.Username
		}

		if json.Password != "" {
			user.Password = utils.HashPassword(json.Password, config.GetConfig().PasswordSalt)
		}

		err = db.Save(&user).Error
		if err != nil {
			logging.Errorf("Error updating user: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "User updated"})
	}
}

func DELETEUser(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	idUint64, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	exists, err := models.UserIDExists(db, uint(idUint64))
	if err != nil {
		logging.Errorf("Error checking if user exists: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking if user exists"})
		return
	}
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User does not exist"})
		return
	}

	err = models.DeleteUser(db, uint(idUint64))
	if err != nil {
		logging.Errorf("Error deleting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}

func POSTUserSuspend(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	id := c.Param("id")

	userID, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid User ID"})
		return
	}
	session := sessions.Default(c)
	fromUserID, ok := session.Get("user_id").(uint)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	if uint(userID) == fromUserID {
		// don't allow a user to demote themselves
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot suspend yourself"})
		return
	}

	// Grab the user from the database
	user, err := models.FindUserByID(db, uint(userID))
	if err != nil {
		logging.Errorf("Error finding user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error finding user"})
		return
	}

	if user.Admin || user.ID == dmrconst.SuperAdminUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot suspend an admin"})
		return
	}

	if user.ID == dmrconst.ParrotUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot suspend the Parrot user"})
		return
	}

	user.Suspended = true
	err = db.Save(&user).Error
	if err != nil {
		logging.Errorf("Error saving user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User suspended"})
}

func GETUserSelf(c *gin.Context) {
	db, ok := c.MustGet("DB").(*gorm.DB)
	if !ok {
		logging.Error("DB cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}
	session := sessions.Default(c)

	userID := session.Get("user_id")
	if userID == nil {
		logging.Error("userID not found")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	uid, ok := userID.(uint)
	if !ok {
		logging.Error("userID cast failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Try again later"})
		return
	}

	user, err := models.FindUserByID(db, uid)
	if err != nil {
		logging.Errorf("Error finding user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error finding user"})
		return
	}
	c.JSON(http.StatusOK, user)
}
