package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Scanner  ScannerConfig  `mapstructure:"scanner"`
}

type ServerConfig struct {
	Host            string `mapstructure:"host" default:"0.0.0.0"`
	Port            int    `mapstructure:"port" default:"8080"`
	Mode            string `mapstructure:"mode" default:"debug"` // debug, release
	ReadTimeout     int    `mapstructure:"read_timeout" default:"30"`
	WriteTimeout    int    `mapstructure:"write_timeout" default:"30"`
	ShutdownTimeout int    `mapstructure:"shutdown_timeout" default:"30"`
	EnableCORS      bool   `mapstructure:"enable_cors" default:"true"`
	TrustedProxies  []string `mapstructure:"trusted_proxies"`
}

type DatabaseConfig struct {
	Driver          string `mapstructure:"driver" default:"sqlite"`
	Host            string `mapstructure:"host" default:"localhost"`
	Port            int    `mapstructure:"port" default:"5432"`
	User            string `mapstructure:"user" default:"postgres"`
	Password        string `mapstructure:"password"`
	Name            string `mapstructure:"name" default:"ics_inventory"`
	SSLMode         string `mapstructure:"ssl_mode" default:"disable"`
	Timezone        string `mapstructure:"timezone" default:"UTC"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns" default:"10"`
	MaxOpenConns    int    `mapstructure:"max_open_conns" default:"100"`
	ConnMaxLifetime int    `mapstructure:"conn_max_lifetime" default:"24"` // hours
	Debug           bool   `mapstructure:"debug" default:"false"`
}

type SecurityConfig struct {
	JWTSecret       string `mapstructure:"jwt_secret" default:"your-secret-key-change-in-production"`
	JWTExpiry       int    `mapstructure:"jwt_expiry" default:"24"` // hours
	PasswordMinLen  int    `mapstructure:"password_min_length" default:"8"`
	EnableAuth      bool   `mapstructure:"enable_auth" default:"true"`
	SessionTimeout  int    `mapstructure:"session_timeout" default:"3600"` // seconds
	RateLimit       int    `mapstructure:"rate_limit" default:"100"` // requests per minute
}

type LoggingConfig struct {
	Level      string `mapstructure:"level" default:"info"`
	Format     string `mapstructure:"format" default:"json"` // json, console
	Output     string `mapstructure:"output" default:"stdout"` // stdout, file
	Filename   string `mapstructure:"filename" default:"logs/app.log"`
	MaxSize    int    `mapstructure:"max_size" default:"100"` // MB
	MaxBackups int    `mapstructure:"max_backups" default:"3"`
	MaxAge     int    `mapstructure:"max_age" default:"28"` // days
	Compress   bool   `mapstructure:"compress" default:"true"`
}

type ScannerConfig struct {
	DefaultTimeout    int      `mapstructure:"default_timeout" default:"30"` // seconds
	MaxConcurrent     int      `mapstructure:"max_concurrent" default:"50"`
	RetryAttempts     int      `mapstructure:"retry_attempts" default:"3"`
	EnableProtocols   []string `mapstructure:"enable_protocols" default:"modbus,dnp3,bacnet"`
	PortRanges        []string `mapstructure:"port_ranges" default:"1-1024,502,20000"`
	ScanInterval      int      `mapstructure:"scan_interval" default:"3600"` // seconds
	EnablePassiveScan bool     `mapstructure:"enable_passive_scan" default:"true"`
}

// Load configuration from file and environment variables
func Load() (*Config, error) {
	config := &Config{}

	// Set configuration file name and paths
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	// Set environment variable prefix
	viper.SetEnvPrefix("ICS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set default values
	setDefaults()

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, using defaults and env vars
	}

	// Unmarshal configuration
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validate(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.mode", "debug")
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)
	viper.SetDefault("server.shutdown_timeout", 30)
	viper.SetDefault("server.enable_cors", true)

	// Database defaults
	viper.SetDefault("database.driver", "sqlite")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.name", "ics_inventory")
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.timezone", "UTC")
	viper.SetDefault("database.max_idle_conns", 10)
	viper.SetDefault("database.max_open_conns", 100)
	viper.SetDefault("database.conn_max_lifetime", 24)
	viper.SetDefault("database.debug", false)

	// Security defaults
	viper.SetDefault("security.jwt_secret", "your-secret-key-change-in-production")
	viper.SetDefault("security.jwt_expiry", 24)
	viper.SetDefault("security.password_min_length", 8)
	viper.SetDefault("security.enable_auth", true)
	viper.SetDefault("security.session_timeout", 3600)
	viper.SetDefault("security.rate_limit", 100)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.filename", "logs/app.log")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 3)
	viper.SetDefault("logging.max_age", 28)
	viper.SetDefault("logging.compress", true)

	// Scanner defaults
	viper.SetDefault("scanner.default_timeout", 30)
	viper.SetDefault("scanner.max_concurrent", 50)
	viper.SetDefault("scanner.retry_attempts", 3)
	viper.SetDefault("scanner.enable_protocols", []string{"modbus", "dnp3", "bacnet"})
	viper.SetDefault("scanner.port_ranges", []string{"1-1024", "502", "20000"})
	viper.SetDefault("scanner.scan_interval", 3600)
	viper.SetDefault("scanner.enable_passive_scan", true)
}

func validate(config *Config) error {
	// Validate server config
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Server.Mode != "debug" && config.Server.Mode != "release" {
		return fmt.Errorf("invalid server mode: %s", config.Server.Mode)
	}

	// Validate database config
	if config.Database.Driver != "sqlite" && config.Database.Driver != "postgres" {
		return fmt.Errorf("unsupported database driver: %s", config.Database.Driver)
	}

	if config.Database.Driver == "postgres" {
		if config.Database.Host == "" {
			return fmt.Errorf("database host is required for postgres")
		}
		if config.Database.User == "" {
			return fmt.Errorf("database user is required for postgres")
		}
	}

	// Validate security config
	if len(config.Security.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	if config.Security.PasswordMinLen < 6 {
		return fmt.Errorf("password minimum length must be at least 6")
	}

	// Validate logging config
	validLevels := []string{"debug", "info", "warn", "error", "fatal"}
	validLevel := false
	for _, level := range validLevels {
		if config.Logging.Level == level {
			validLevel = true
			break
		}
	}
	if !validLevel {
		return fmt.Errorf("invalid logging level: %s", config.Logging.Level)
	}

	return nil
}

// GetString returns string configuration value
func (c *Config) GetString(key string) string {
	return viper.GetString(key)
}

// GetInt returns integer configuration value
func (c *Config) GetInt(key string) int {
	return viper.GetInt(key)
}

// GetBool returns boolean configuration value  
func (c *Config) GetBool(key string) bool {
	return viper.GetBool(key)
}
