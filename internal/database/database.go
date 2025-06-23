package database

import (
	"fmt"
	"log"
	"time"

	"ics-asset-inventory/internal/config"
	"ics-asset-inventory/internal/database/models"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	DB           *gorm.DB
	CurrentDriver string // Store current driver
	queryBuilder *QueryBuilder
)

// Initialize database connection
func Initialize(cfg *config.Config) error {
	var err error
	var dialector gorm.Dialector

	// Store the driver type
	CurrentDriver = cfg.Database.Driver

	// Choose database driver based on config
	switch cfg.Database.Driver {
	case "postgres":
		dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s TimeZone=%s",
			cfg.Database.Host,
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.Name,
			cfg.Database.Port,
			cfg.Database.SSLMode,
			cfg.Database.Timezone,
		)
		dialector = postgres.Open(dsn)
	case "sqlite":
		dialector = sqlite.Open(cfg.Database.Name + ".db")
	default:
		return fmt.Errorf("unsupported database driver: %s", cfg.Database.Driver)
	}

	// Configure GORM logger
	var gormLogger logger.Interface
	if cfg.Database.Debug {
		gormLogger = logger.Default.LogMode(logger.Info)
	} else {
		gormLogger = logger.Default.LogMode(logger.Silent)
	}

	// Open database connection
	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.Database.ConnMaxLifetime) * time.Hour)

	// Initialize query builder
	queryBuilder = NewQueryBuilder(CurrentDriver)

	log.Println("✅ Database connected successfully")
	return nil
}

// GetQueryBuilder returns the query builder instance
func GetQueryBuilder() *QueryBuilder {
	if queryBuilder == nil {
		queryBuilder = NewQueryBuilder(CurrentDriver)
	}
	return queryBuilder
}

// TestConnection tests database connectivity
func TestConnection() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

// AutoMigrate runs database migrations
func AutoMigrate() error {
	err := DB.AutoMigrate(
		&models.Asset{},
		&models.AssetGroup{},
		&models.AssetTag{},
		&models.AssetAttribute{},
		&models.NetworkScan{},
		&models.SecurityAssessment{},
		&models.User{},
		&models.SystemConfig{},
	)
	if err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Setup join tables for many-to-many relationships
	if err := DB.SetupJoinTable(&models.Asset{}, "Tags", &models.AssetTag{}); err != nil {
		log.Printf("Warning: Failed to setup asset_tags join table: %v", err)
		// Don't return error as it might already exist
	}

	log.Println("✅ Database migrations completed")
	return nil
}

// SeedData inserts initial data
func SeedData() error {
	// Create default asset groups
	if err := seedAssetGroups(); err != nil {
		return err
	}

	// Create default tags
	if err := seedAssetTags(); err != nil {
		return err
	}

	// Create default admin user
	if err := seedUsers(); err != nil {
		return err
	}

	// Create default system configurations
	if err := seedSystemConfigs(); err != nil {
		return err
	}

	log.Println("✅ Database seeded successfully")
	return nil
}

func seedAssetGroups() error {
	defaultGroups := []models.AssetGroup{
		{Name: "PLCs", Description: "Programmable Logic Controllers", Color: "#10B981"},
		{Name: "HMIs", Description: "Human Machine Interfaces", Color: "#3B82F6"},
		{Name: "RTUs", Description: "Remote Terminal Units", Color: "#F59E0B"},
		{Name: "Switches", Description: "Network Switches", Color: "#8B5CF6"},
		{Name: "Servers", Description: "Industrial Servers", Color: "#EF4444"},
		{Name: "Sensors", Description: "Industrial Sensors", Color: "#06B6D4"},
	}

	for _, group := range defaultGroups {
		var existing models.AssetGroup
		result := DB.Where("name = ?", group.Name).First(&existing)
		if result.Error == gorm.ErrRecordNotFound {
			if err := DB.Create(&group).Error; err != nil {
				return fmt.Errorf("failed to create group %s: %w", group.Name, err)
			}
		}
	}
	return nil
}

func seedAssetTags() error {
	defaultTags := []models.AssetTag{
		{Name: "Critical", Color: "#DC2626"},
		{Name: "Production", Color: "#059669"},
		{Name: "Development", Color: "#7C3AED"},
		{Name: "Maintenance", Color: "#D97706"},
		{Name: "Monitoring", Color: "#0891B2"},
		{Name: "Safety", Color: "#EA580C"},
		{Name: "Remote", Color: "#4338CA"},
	}

	for _, tag := range defaultTags {
		var existing models.AssetTag
		result := DB.Where("name = ?", tag.Name).First(&existing)
		if result.Error == gorm.ErrRecordNotFound {
			if err := DB.Create(&tag).Error; err != nil {
				return fmt.Errorf("failed to create tag %s: %w", tag.Name, err)
			}
		}
	}
	return nil
}

func seedUsers() error {
	var adminUser models.User
	result := DB.Where("username = ?", "admin").First(&adminUser)
	if result.Error == gorm.ErrRecordNotFound {
		admin := models.User{
			Username: "admin",
			Email:    "admin@localhost",
			Password: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", // "admin123" with SHA256
			Role:     "admin",
			Active:   true,
		}
		if err := DB.Create(&admin).Error; err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}
	}
	return nil
}

func seedSystemConfigs() error {
	defaultConfigs := []models.SystemConfig{
		{Key: "app.name", Value: "ICS Asset Inventory", ValueType: "string", Description: "Application name", Category: "general"},
		{Key: "app.version", Value: "1.0.0", ValueType: "string", Description: "Application version", Category: "general"},
		{Key: "scan.default_timeout", Value: "30", ValueType: "number", Description: "Default scan timeout in seconds", Category: "scanning"},
		{Key: "security.session_timeout", Value: "3600", ValueType: "number", Description: "Session timeout in seconds", Category: "security"},
		{Key: "monitoring.update_interval", Value: "60", ValueType: "number", Description: "Monitoring update interval in seconds", Category: "monitoring"},
	}

	for _, config := range defaultConfigs {
		var existing models.SystemConfig
		result := DB.Where("key = ?", config.Key).First(&existing)
		if result.Error == gorm.ErrRecordNotFound {
			if err := DB.Create(&config).Error; err != nil {
				return fmt.Errorf("failed to create config %s: %w", config.Key, err)
			}
		}
	}
	return nil
}

// GetDB returns database instance
func GetDB() *gorm.DB {
	return DB
}

// Close database connection
func Close() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// GetStats returns database statistics
func GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	var assetCount, groupCount, tagCount int64
	DB.Model(&models.Asset{}).Count(&assetCount)
	DB.Model(&models.AssetGroup{}).Count(&groupCount)
	DB.Model(&models.AssetTag{}).Count(&tagCount)
	
	stats["assets"] = assetCount
	stats["groups"] = groupCount
	stats["tags"] = tagCount
	stats["driver"] = CurrentDriver
	
	return stats
}