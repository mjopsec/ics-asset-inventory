# ICS Asset Inventory

> Comprehensive asset inventory system for Industrial Control Systems (ICS/OT) environments

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![Status](https://img.shields.io/badge/status-alpha-yellow.svg)

## 🎯 Overview

ICS Asset Inventory adalah sistem manajemen aset yang dirancang khusus untuk lingkungan Industrial Control Systems (ICS) dan Operational Technology (OT). Sistem ini memberikan visibilitas real-time terhadap perangkat industri dan membantu dalam pengelolaan keamanan infrastruktur kritis.

## ✨ Fitur Unggulan

### 🔍 **Network Discovery**
- **Passive Scanning**: Monitoring jaringan tanpa mengganggu operasi
- **Protocol Detection**: Support Modbus, DNP3, EtherNet/IP, BACnet
- **Auto Asset Classification**: Identifikasi otomatis jenis perangkat

### 🛡️ **Security Assessment**
- **Vulnerability Scanning**: Khusus untuk protokol ICS/OT
- **Compliance Reporting**: IEC 62443, NIST standards
- **Risk Assessment**: Penilaian risiko berbasis criticality

### 📊 **Real-time Monitoring**
- **Live Status**: Monitoring status operasional device
- **Network Topology**: Visualisasi jaringan industrial
- **Alert System**: Notifikasi real-time untuk anomali

### 📈 **Advanced Analytics**
- **Trend Analysis**: Analisis tren performa device
- **Capacity Planning**: Prediksi kebutuhan infrastruktur
- **Custom Dashboards**: Dashboard yang dapat dikustomisasi

## 🚀 Quick Start

### Prerequisites

- Go 1.21 atau lebih tinggi
- Git

### Installation

1. **Clone repository**
```bash
git clone https://github.com/your-org/ics-asset-inventory.git
cd ics-asset-inventory
```

2. **Setup environment**
```bash
make setup
```

3. **Install dependencies**
```bash
make deps
```

4. **Run aplikasi**
```bash
make run
```

5. **Akses dashboard**
```
http://localhost:8080
```

## 📁 Struktur Project

```
ics-asset-inventory/
├── cmd/                    # Main applications
│   ├── server/            # Web server
│   ├── scanner/           # Network scanner CLI
│   └── cli/               # Management CLI
├── internal/              # Internal packages
│   ├── api/               # HTTP API layer
│   │   ├── handlers/      # Request handlers
│   │   ├── middleware/    # HTTP middleware
│   │   └── routes/        # Route definitions
│   ├── config/            # Configuration management
│   ├── database/          # Database layer
│   │   ├── models/        # Data models
│   │   └── migrations/    # Database migrations
│   ├── services/          # Business logic
│   │   ├── discovery/     # Network discovery
│   │   ├── monitoring/    # Real-time monitoring
│   │   ├── security/      # Security assessment
│   │   └── reporting/     # Report generation
│   └── protocols/         # Protocol implementations
│       ├── modbus/        # Modbus TCP/RTU
│       ├── dnp3/          # DNP3 protocol
│       └── ethernet_ip/   # EtherNet/IP
├── web/                   # Web UI assets
│   ├── static/            # Static files
│   ├── templates/         # HTML templates
│   └── assets/            # CSS, JS, images
├── pkg/                   # Public packages
├── configs/               # Configuration files
├── scripts/               # Utility scripts
├── docs/                  # Documentation
└── docker/               # Docker configurations
```

## 🛠️ Development

### Available Commands

```bash
# Development
make dev          # Run with auto-reload
make run          # Run application
make build        # Build binary

# Code Quality
make test         # Run tests
make lint         # Run linter
make fmt          # Format code
make check        # Run all checks

# Database
make migrate      # Run migrations
make seed         # Seed sample data

# Docker
make docker-build # Build image
make docker-run   # Run container
```

### Configuration

Edit `configs/config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  mode: "debug"

database:
  driver: "sqlite"  # or "postgres"
  name: "ics_inventory"

scanner:
  enable_protocols:
    - "modbus"
    - "dnp3"
    - "bacnet"
  scan_interval: 3600
```

## 📊 API Documentation

### Assets API

```bash
# Get all assets
GET /api/assets

# Get asset by ID
GET /api/assets/{id}

# Create new asset
POST /api/assets

# Update asset
PUT /api/assets/{id}

# Delete asset
DELETE /api/assets/{id}

# Get asset statistics
GET /api/assets/stats
```

### Groups API

```bash
# Manage asset groups
GET    /api/groups
POST   /api/groups
GET    /api/groups/{id}
PUT    /api/groups/{id}
DELETE /api/groups/{id}
```

### Dashboard API

```bash
# Dashboard data
GET /api/dashboard/overview
GET /api/dashboard/metrics
GET /api/dashboard/alerts
```

## 🔧 Protocol Support

### Modbus TCP/RTU
- Device enumeration
- Register reading
- Function code analysis
- Exception handling

### DNP3
- Outstation discovery
- Object variation support
- Event monitoring
- Security authentication

### EtherNet/IP
- CIP device identification
- Assembly object reading
- Connection monitoring
- Vendor-specific extensions

### BACnet
- Device discovery
- Object enumeration
- Property reading
- Network layer analysis

## 🛡️ Security Features

### Vulnerability Assessment
- **Protocol-specific checks**: Known vulnerabilities untuk setiap protokol
- **Configuration analysis**: Audit konfigurasi keamanan
- **Credential testing**: Default password detection
- **Certificate validation**: SSL/TLS certificate checks

### Compliance Reporting
- **IEC 62443**: Industrial security standards
- **NIST Cybersecurity Framework**: Comprehensive security assessment
- **Custom policies**: Definisi policy sesuai kebutuhan organisasi

## 📈 Monitoring & Alerting

### Real-time Monitoring
- Device status (online/offline/error)
- Performance metrics
- Communication quality
- Protocol-specific parameters

### Alert Categories
- **Device offline**: Perangkat tidak dapat dijangkau
- **Security threats**: Deteksi ancaman keamanan
- **Performance degradation**: Penurunan performa
- **Configuration changes**: Perubahan konfigurasi

## 🤝 Contributing

Kami welcome kontribusi dari komunitas! Silakan:

1. Fork repository
2. Buat feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push ke branch (`git push origin feature/amazing-feature`)
5. Buat Pull Request

### Development Guidelines

- Follow Go best practices
- Write tests untuk new features
- Update documentation
- Use conventional commits
- Ensure backward compatibility

## 📝 License

Project ini dilisensikan di bawah MIT License - lihat file [LICENSE](LICENSE) untuk detail.

## 🙏 Acknowledgments

- [Gin Framework](https://gin-gonic.com/) - HTTP web framework
- [GORM](https://gorm.io/) - ORM library
- [Chart.js](https://www.chartjs.org/) - Chart visualization
- [Tailwind CSS](https://tailwindcss.com/) - CSS framework
- [HTMX](https://htmx.org/) - Modern web interactions

## 📞 Support

- 📧 Email: support@example.com
- 💬 Discord: [Join our community](https://discord.gg/example)
- 📖 Documentation: [docs.example.com](https://docs.example.com)
- 🐛 Bug Reports: [GitHub Issues](https://github.com/your-org/ics-asset-inventory/issues)

---

**Made with ❤️ for the ICS/OT Security Community**
