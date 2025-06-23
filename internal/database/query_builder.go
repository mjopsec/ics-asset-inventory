package database

import (
	"fmt"
	"strings"
)

// QueryBuilder helps build database-specific queries
type QueryBuilder struct {
	driver string
}

// NewQueryBuilder creates a new query builder instance
func NewQueryBuilder(driver string) *QueryBuilder {
	return &QueryBuilder{driver: driver}
}

// BuildSearchQuery builds a search query compatible with the database driver
func (qb *QueryBuilder) BuildSearchQuery(fields []string, paramCount int) string {
	if qb.driver == "sqlite" {
		var conditions []string
		for _, field := range fields {
			conditions = append(conditions, fmt.Sprintf("LOWER(%s) LIKE LOWER(?)", field))
		}
		return strings.Join(conditions, " OR ")
	}
	
	// PostgreSQL supports ILIKE
	var conditions []string
	for _, field := range fields {
		conditions = append(conditions, fmt.Sprintf("%s ILIKE ?", field))
	}
	return strings.Join(conditions, " OR ")
}

// BuildOrderBy builds an ORDER BY clause compatible with the database driver
func (qb *QueryBuilder) BuildOrderBy(field string, direction string) string {
	// Validate direction
	direction = strings.ToUpper(direction)
	if direction != "ASC" && direction != "DESC" {
		direction = "ASC"
	}
	
	// For SQLite, we might need special handling for certain fields
	if qb.driver == "sqlite" {
		// Handle case-insensitive sorting for text fields
		switch field {
		case "name", "description", "vendor", "model":
			return fmt.Sprintf("LOWER(%s) %s", field, direction)
		default:
			return fmt.Sprintf("%s %s", field, direction)
		}
	}
	
	return fmt.Sprintf("%s %s", field, direction)
}

// GetDriver returns the current database driver
func (qb *QueryBuilder) GetDriver() string {
	return qb.driver
}