package models

import (
	"time"

	"github.com/USA-RedDragon/dmrserver-in-a-box/config"
	"github.com/USA-RedDragon/dmrserver-in-a-box/http/api/utils"
	gorm_seeder "github.com/kachit/gorm-seeder"
	"gorm.io/gorm"
	"k8s.io/klog/v2"
)

type User struct {
	ID        uint           `json:"id" gorm:"primaryKey" binding:"required"`
	Callsign  string         `json:"callsign" gorm:"uniqueIndex" binding:"required"`
	Username  string         `json:"username" gorm:"uniqueIndex" binding:"required"`
	Password  string         `json:"-"`
	Admin     bool           `json:"admin"`
	Approved  bool           `json:"approved" binding:"required"`
	Repeaters []Repeater     `json:"repeaters" gorm:"foreignKey:OwnerID"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

func (u User) TableName() string {
	return "users"
}

func UserExists(db *gorm.DB, user User) bool {
	var count int64
	db.Model(&User{}).Where("ID = ?", user.ID).Limit(1).Count(&count)
	return count > 0
}

func UserIDExists(db *gorm.DB, id uint) bool {
	var count int64
	db.Model(&User{}).Where("ID = ?", id).Limit(1).Count(&count)
	return count > 0
}

func FindUserByID(db *gorm.DB, ID uint) User {
	var user User
	db.Preload("Repeaters").First(&user, ID)
	return user
}

func ListUsers(db *gorm.DB) []User {
	var users []User
	db.Preload("Repeaters").Find(&users)
	return users
}

type UsersSeeder struct {
	gorm_seeder.SeederAbstract
}

func NewUsersSeeder(cfg gorm_seeder.SeederConfiguration) UsersSeeder {
	return UsersSeeder{gorm_seeder.NewSeederAbstract(cfg)}
}

func (s *UsersSeeder) Seed(db *gorm.DB) error {
	var users = []User{
		{
			ID:       uint(9990),
			Callsign: "Parrot",
			Admin:    false,
			Approved: true,
		},
		{
			ID:       999999,
			Callsign: "SystemAdmin",
			Username: "Admin",
			Admin:    true,
			Approved: true,
			Password: utils.HashPassword(config.GetConfig().InitialAdminUserPassword, config.GetConfig().PasswordSalt),
		},
	}
	klog.Errorf("!#!#!#!#!# Initial admin user password: %s #!#!#!#!#!", config.GetConfig().InitialAdminUserPassword)
	return db.CreateInBatches(users, s.Configuration.Rows).Error
}

func (s *UsersSeeder) Clear(db *gorm.DB) error {
	return nil
}
