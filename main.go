package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/USA-RedDragon/dmrserver-in-a-box/dmr"
	"github.com/USA-RedDragon/dmrserver-in-a-box/http"
	"github.com/USA-RedDragon/dmrserver-in-a-box/models"
	"github.com/USA-RedDragon/dmrserver-in-a-box/repeaterdb"
	"github.com/USA-RedDragon/dmrserver-in-a-box/sdk"
	"github.com/USA-RedDragon/dmrserver-in-a-box/userdb"
	"k8s.io/klog/v2"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var verbose = flag.Bool("verbose", false, "Whether to display verbose logs")

func main() {
	defer klog.Flush()
	klog.Infof("DMR Network in a box v%s-%s", sdk.Version, sdk.GitCommit)
	var redisHost = flag.String("redis", "localhost:6379", "The hostname of redis")
	var listen = flag.String("listen", "0.0.0.0", "The IP to listen on")
	var secret = flag.String("secret", "", "The session encryption secret")
	var dmrPort = flag.Int("dmr-port", 62031, "The Port to listen on")
	var frontendPort = flag.Int("frontend-port", 3005, "The Port to listen on")

	flag.Parse()

	if *secret == "" {
		klog.Exit("You must specify a secret")
	}

	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		klog.Errorf("Failed to open database: %s", err)
	}
	db.AutoMigrate(&models.Call{}, &models.Repeater{}, &models.Talkgroup{}, &models.User{})
	if db.Error != nil {
		//We have an error
		klog.Exitf(fmt.Sprintf("Failed with error %s", db.Error))
	}
	sqlDB, err := db.DB()
	if err != nil {
		klog.Exitf("Failed to open database: %s", err)
		return
	}
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Dummy call to get the data decoded into memory early
	userdb.GetDMRUsers()
	repeaterdb.GetDMRRepeaters()

	dmrServer := dmr.MakeServer(*listen, *dmrPort, *redisHost, *verbose, db)
	go dmrServer.Listen()
	defer dmrServer.Stop()

	corsHosts := []string{"http://localhost:3005", "http://localhost:5173", "http://127.0.0.1:3005", "http://127.0.0.1:5173", "http://192.168.1.90:5173", "http://192.168.1.90:3005", "http://ki5vmf-server.local.mesh:3005"}
	http.Start(*listen, *frontendPort, *verbose, *redisHost, db, *secret, corsHosts)
}
