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

package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/USA-RedDragon/DMRHub/internal/http/api/utils"
	"github.com/USA-RedDragon/DMRHub/internal/logging"
	"golang.org/x/crypto/pbkdf2"
)

// Config stores the application configuration.
type Config struct {
	RedisHost                string
	RedisPassword            string
	PostgresDSN              string
	postgresUser             string
	postgresPassword         string
	postgresHost             string
	postgresPort             int
	postgresDatabase         string
	Secret                   []byte
	strSecret                string
	PasswordSalt             string
	ListenAddr               string
	DMRPort                  int
	MetricsPort              int
	OpenBridgePort           int
	HTTPPort                 int
	CORSHosts                []string
	TrustedProxies           []string
	HIBPAPIKey               string
	OTLPEndpoint             string
	InitialAdminUserPassword string
	Debug                    bool
	NetworkName              string
	AllowScraping            bool
	CustomRobotsTxt          string
	FeatureFlags             []string
	SMTPHost                 string
	SMTPPort                 int
	SMTPImplicitTLS          bool
	SMTPUsername             string
	SMTPPassword             string
	SMTPFrom                 string
	SMTPAuthMethod           string
	AdminEmail               string
	EnableEmail              bool
	CanonicalHost            string
	EnforceRadioid		 bool
}

var currentConfig atomic.Value //nolint:golint,gochecknoglobals
var isInit atomic.Bool         //nolint:golint,gochecknoglobals
var loaded atomic.Bool         //nolint:golint,gochecknoglobals

func loadConfig() Config {
	portStr := os.Getenv("PG_PORT")
	pgPort, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		pgPort = 0
	}

	portStr = os.Getenv("DMR_PORT")
	dmrPort, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		dmrPort = 0
	}

	portStr = os.Getenv("HTTP_PORT")
	httpPort, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		httpPort = 0
	}

	portStr = os.Getenv("OPENBRIDGE_PORT")
	openBridgePort, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		openBridgePort = 0
	}

	portStr = os.Getenv("METRICS_PORT")
	metricsPort, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		metricsPort = 0
	}

	portStr = os.Getenv("SMTP_PORT")
	smtpPort, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		smtpPort = 0
	}

	tmpConfig := Config{
		RedisHost:                os.Getenv("REDIS_HOST"),
		postgresUser:             os.Getenv("PG_USER"),
		postgresPassword:         os.Getenv("PG_PASSWORD"),
		postgresHost:             os.Getenv("PG_HOST"),
		postgresPort:             int(pgPort),
		postgresDatabase:         os.Getenv("PG_DATABASE"),
		strSecret:                os.Getenv("SECRET"),
		PasswordSalt:             os.Getenv("PASSWORD_SALT"),
		ListenAddr:               os.Getenv("LISTEN_ADDR"),
		DMRPort:                  int(dmrPort),
		HTTPPort:                 int(httpPort),
		MetricsPort:              int(metricsPort),
		HIBPAPIKey:               os.Getenv("HIBP_API_KEY"),
		OTLPEndpoint:             os.Getenv("OTLP_ENDPOINT"),
		InitialAdminUserPassword: os.Getenv("INIT_ADMIN_USER_PASSWORD"),
		RedisPassword:            os.Getenv("REDIS_PASSWORD"),
		Debug:                    os.Getenv("DEBUG") != "",
		NetworkName:              os.Getenv("NETWORK_NAME"),
		AllowScraping:            os.Getenv("ALLOW_SCRAPING") != "",
		CustomRobotsTxt:          os.Getenv("CUSTOM_ROBOTS_TXT"),
		OpenBridgePort:           int(openBridgePort),
		SMTPHost:                 os.Getenv("SMTP_HOST"),
		SMTPPort:                 int(smtpPort),
		SMTPImplicitTLS:          os.Getenv("SMTP_IMPLICIT_TLS") != "",
		SMTPUsername:             os.Getenv("SMTP_USERNAME"),
		SMTPPassword:             os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:                 os.Getenv("SMTP_FROM"),
		SMTPAuthMethod:           os.Getenv("SMTP_AUTH_METHOD"),
		AdminEmail:               os.Getenv("ADMIN_EMAIL"),
		EnableEmail:              os.Getenv("ENABLE_EMAIL") != "",
		CanonicalHost:            os.Getenv("CANONICAL_HOST"),
		EnforceRadioid:		  os.Getenv("ENFORCE_RADIOID") != "0",
	}
	if tmpConfig.RedisHost == "" {
		tmpConfig.RedisHost = "localhost:6379"
	}
	if tmpConfig.postgresUser == "" {
		tmpConfig.postgresUser = "postgres"
	}
	if tmpConfig.postgresPassword == "" {
		tmpConfig.postgresPassword = "password"
	}
	if tmpConfig.postgresHost == "" {
		tmpConfig.postgresHost = "localhost"
	}
	if tmpConfig.postgresPort == 0 {
		tmpConfig.postgresPort = 5432
	}
	if tmpConfig.postgresDatabase == "" {
		tmpConfig.postgresDatabase = "postgres"
	}
	tmpConfig.PostgresDSN = "host=" + tmpConfig.postgresHost + " port=" + strconv.FormatInt(int64(tmpConfig.postgresPort), 10) + " user=" + tmpConfig.postgresUser + " dbname=" + tmpConfig.postgresDatabase + " password=" + tmpConfig.postgresPassword
	if tmpConfig.strSecret == "" {
		tmpConfig.strSecret = "secret"
		logging.Error("SECRET not set, using INSECURE default")
	}
	if tmpConfig.PasswordSalt == "" {
		tmpConfig.PasswordSalt = "salt"
		logging.Error("PASSWORD_SALT not set, using INSECURE default")
	}
	if tmpConfig.ListenAddr == "" {
		tmpConfig.ListenAddr = "0.0.0.0"
	}
	if tmpConfig.DMRPort == 0 {
		tmpConfig.DMRPort = 62031
	}
	if tmpConfig.OpenBridgePort == 0 {
		logging.Error("OPENBRIDGE_PORT not set, disabling OpenBridge support")
	}
	if tmpConfig.HTTPPort == 0 {
		tmpConfig.HTTPPort = 3005
	}
	if tmpConfig.NetworkName == "" {
		tmpConfig.NetworkName = "DMRHub"
	}
	if tmpConfig.InitialAdminUserPassword == "" {
		logging.Error("INIT_ADMIN_USER_PASSWORD not set, using auto-generated password")
		const randLen = 15
		const randNums = 4
		const randSpecial = 2
		tmpConfig.InitialAdminUserPassword, err = utils.RandomPassword(randLen, randNums, randSpecial)
		if err != nil {
			logging.Error("Password generation failed")
			os.Exit(1)
		}
	}
	if tmpConfig.RedisPassword == "" {
		tmpConfig.RedisPassword = "password"
		logging.Error("REDIS_PASSWORD not set, using INSECURE default")
	}
	// CORS_HOSTS is a comma separated list of hosts that are allowed to access the API
	corsHosts := os.Getenv("CORS_HOSTS")
	if corsHosts == "" {
		tmpConfig.CORSHosts = []string{
			fmt.Sprintf("http://localhost:%d", tmpConfig.HTTPPort),
			fmt.Sprintf("http://127.0.0.1:%d", tmpConfig.HTTPPort),
		}
	} else {
		tmpConfig.CORSHosts = strings.Split(corsHosts, ",")
	}
	// FEATURE_FLAGS is a comma separated list of enabled feature flags
	featureFlags := os.Getenv("FEATURE_FLAGS")
	if featureFlags == "" {
		tmpConfig.FeatureFlags = []string{}
	} else {
		tmpConfig.FeatureFlags = strings.Split(featureFlags, ",")
	}
	trustedProxies := os.Getenv("TRUSTED_PROXIES")
	if trustedProxies == "" {
		tmpConfig.TrustedProxies = []string{}
	} else {
		tmpConfig.TrustedProxies = strings.Split(trustedProxies, ",")
	}

	if tmpConfig.CanonicalHost == "" {
		tmpConfig.CanonicalHost = "localhost"
	}

	switch tmpConfig.SMTPAuthMethod {
	case "PLAIN":
	case "LOGIN":
	default:
		logging.Error("SMTP_AUTH_METHOD not set to a valid value. You can ignore this if you are not using email features.")
	}

	if tmpConfig.Debug {
		logging.Error("Debug mode enabled, this should not be used in production")
		logging.Errorf("Config: %+v", tmpConfig)
	}
	const iterations = 4096
	const keyLen = 32
	tmpConfig.Secret = pbkdf2.Key([]byte(tmpConfig.strSecret), []byte(tmpConfig.PasswordSalt), iterations, keyLen, sha256.New)
	return tmpConfig
}

// GetConfig obtains the current configuration
// On the first call, it will load the configuration from the environment variables.
func GetConfig() *Config {
	lastInit := isInit.Swap(true)
	if !lastInit {
		currentConfig.Store(loadConfig())
		loaded.Store(true)
	}
	for !loaded.Load() {
		const loadDelay = 100 * time.Millisecond
		time.Sleep(loadDelay)
	}

	curConfig, ok := currentConfig.Load().(Config)
	if !ok {
		logging.Error("Failed to load config")
		os.Exit(1)
	}
	return &curConfig
}
