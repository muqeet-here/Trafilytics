# Trafilytics

A privacy-compliant billboard analytics system built on ESP32 with cellular connectivity for real-time audience measurement and analytics.

## Overview

Trafilytics is an IoT-based billboard analytics platform that provides aggregate audience measurement through passive WiFi scanning. The system is designed with privacy-first principles, ensuring full compliance with US privacy laws including CCPA, FTC Act, and state privacy regulations.

## Key Features

- **Privacy-First Design**: MAC addresses are never stored or transmitted in plaintext
- **Secure Hashing**: FNV-1a hashing with ephemeral salts for one-way encryption
- **Real-time Analytics**: Cellular connectivity (SIM7600) for instant data transmission
- **Cloud Integration**: Firebase backend for data storage and analytics
- **Aggregate Metrics**: No personal data collection or device tracking capability
- **GPS Tracking**: Location awareness for billboard placement analytics

## Privacy Compliance

This system is fully compliant with:
- California Consumer Privacy Act (CCPA)
- Federal Trade Commission (FTC) Act
- State privacy regulations

### Privacy Safeguards:
- ✅ MAC addresses are hashed using FNV-1a with ephemeral salts
- ✅ One-way encryption prevents reverse-engineering
- ✅ In-memory only processing - no persistent storage of identifiers
- ✅ Data cleared on power cycle
- ✅ Aggregated metrics only
- ✅ Zero personal identification capability

## Hardware Requirements

- **Microcontroller**: ESP32 Development Board
- **Cellular Modem**: SIM7600 (4G LTE)
- **Power**: Appropriate power supply for ESP32 and SIM7600

### Pin Configuration

```cpp
MODEM_TX: GPIO 17
MODEM_RX: GPIO 16
SD_CS_PIN: GPIO 5
```

## Software Dependencies

### PlatformIO Libraries:
- ESP32 Arduino Framework
- TinyGSM (Cellular modem)
- FirebaseClient (Cloud database)
- ArduinoJson (JSON processing)
- WiFi (ESP32 scanning)
- SD & SPI (Data logging)

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/muqeet-here/Trafilytics.git
cd Trafilytics
```

### 2. Configure Credentials

Create a `include/credentials.h` file with your configuration:

```cpp
// Billboard Configuration
#define BILLBOARD_IDS "YOUR_BILLBOARD_ID"

// Cellular Network
#define CELLULAR_APN "your.apn.here"
#define CELLULAR_USER "username"
#define CELLULAR_PASS "password"

// Firebase Configuration
#define FIREBASE_API_KEY "your_firebase_api_key"
#define FIREBASE_AUTH_EMAIL "your_email@example.com"
#define FIREBASE_AUTH_PASSWORD "your_password"
#define FIREBASE_DATABASE_URL "https://your-project.firebaseio.com"
```

### 3. Build and Upload

Using PlatformIO:

```bash
pio run -t upload
```

Or use the PlatformIO IDE in VS Code.

### 4. Monitor Serial Output

```bash
pio device monitor
```

## Configuration Options

Edit `src/main.cpp` to adjust system parameters:

```cpp
#define SCAN_INTERVAL_MS 5000        // WiFi scan interval
#define SCANS_PER_UPLOAD 10          // Scans before upload
#define MAX_NETWORKS_PER_SCAN 20     // Safety limit
```

## System Architecture

```
ESP32 (WiFi Scanner)
    ↓
[Hash MAC Addresses]
    ↓
[Aggregate Metrics]
    ↓
SIM7600 (Cellular Modem)
    ↓
Firebase (Cloud Database)
    ↓
Analytics Dashboard
```

## Data Flow

1. **WiFi Scanning**: Passive scanning every 5 seconds
2. **Hashing**: MAC addresses hashed with ephemeral salts
3. **Deduplication**: Tracks unique vs. repeated detections
4. **Aggregation**: Counts impressions and unique networks
5. **Upload**: Transmits aggregate data to Firebase
6. **Storage**: Both cloud (Firebase) and local (SD card) backup

## Metrics Collected

- Total WiFi networks detected
- Unique network count per cycle
- Repeated network count per cycle
- Impression count (billboard views)
- GPS location data
- Timestamp information
- Device uptime and health metrics

## Project Structure

```
Trafilytics/
├── src/
│   ├── main.cpp           # Main application code
│   └── main.cpp.bak       # Backup
├── include/
│   ├── credentials.h      # Configuration (not in repo)
│   └── README             
├── lib/                   # Custom libraries
├── test/                  # Test files
├── platformio.ini         # PlatformIO configuration
├── firestore.rules        # Firebase security rules
└── README.md             # This file
```

## Development

### Building

```bash
pio run
```

### Uploading

```bash
pio run -t upload
```

### Serial Monitor

```bash
pio device monitor -b 115200
```

## Troubleshooting

### Common Issues:

1. **SIM7600 not responding**: Check UART connections and power supply
2. **WiFi scan errors**: Ensure ESP32 WiFi is enabled
3. **Firebase connection fails**: Verify credentials and internet connectivity

## Author

Muqeet (@muqeet-here)

---

**Note**: This system is designed for aggregate audience measurement only and does not track, identify, or store any personal information. All data processing is privacy-compliant and follows industry best practices.
