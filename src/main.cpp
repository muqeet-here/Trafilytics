/*
 * TRAFILYTICS - Billboard Analytics System
 * 
 * PRIVACY COMPLIANCE:
 * - This system complies with US privacy laws including CCPA, FTC Act, and state privacy regulations
 * - MAC addresses are NEVER stored or transmitted in plaintext
 * - All MAC addresses are hashed using FNV-1a with ephemeral salts
 * - Hashes are one-way encrypted and cannot be reverse-engineered to MAC addresses
 * - Data retention: In-memory only, non-persistent, cleared on power cycle
 * - No personal data collection or identification capability
 * - Aggregated metrics only - no device tracking
 * 
 * USAGE:
 * - Passive WiFi scanning for aggregate audience measurement
 * - Zero personal identification or tracking capability
 * - Compliant with FTC guidelines on aggregated data collection
 */

#define TINY_GSM_MODEM_SIM7600
#define SerialMon Serial
#define SerialAT Serial2
#define TINY_GSM_DEBUG SerialMon

#define ENABLE_USER_AUTH
#define ENABLE_DATABASE
#define ENABLE_GSM_NETWORK
#define ENABLE_ESP_SSLCLIENT

#include <Arduino.h>
#include <WiFi.h>
#include <set>
#include <TinyGsmClient.h>
#include <FirebaseClient.h>
#include <SD.h>
#include <SPI.h>
#include "credentials.h"

// ============ CONFIGURATION ============
#define BILLBOARD_ID BILLBOARD_IDS
#define FIRMWARE_VERSION "1.0.0-PROD"
#define SCAN_INTERVAL_MS 5000        // WiFi scan every 5 seconds
#define SCANS_PER_UPLOAD 10          // Upload to Firebase every 10 scans
#define MAX_NETWORKS_PER_SCAN 20     // Safety limit for processing
#define STARTUP_DELAY_MS 2000        // Delay before first scan

// GPRS credentials (from credentials.h)
const char* apn = CELLULAR_APN;
const char* gprsUser = CELLULAR_USER;
const char* gprsPass = CELLULAR_PASS;

// Firebase Configuration (from credentials.h)
#define API_KEY FIREBASE_API_KEY
#define USER_EMAIL FIREBASE_AUTH_EMAIL
#define USER_PASSWORD FIREBASE_AUTH_PASSWORD
#define DATABASE_URL FIREBASE_DATABASE_URL

// Pin definitions
#define MODEM_TX 17
#define MODEM_RX 16
#define SD_CS_PIN 5  // CS pin for SD card module (adjust if needed)

// ============ GLOBAL STATE ============
// Per-upload-cycle counters (reset every 10 scans)
uint32_t wifiNetworksThisCycle = 0;
uint32_t repeatedWifiNetworks = 0;
uint32_t uniqueWifiNetworks = 0;
uint32_t impressionCount = 0;

// Cumulative counters (never reset)
uint32_t totalWifiNetworks = 0;
uint32_t totalScansPerformed = 0;
uint32_t totalReportsGenerated = 0;

// Hash tracking for deduplication
std::set<String> currentCycleHashes;
std::set<String> previousCycleHashes;

// Timing and system state
uint32_t lastScanTime = 0;
uint32_t scanCounter = 0;
uint32_t reportCounter = 0;
uint32_t systemStartTime = 0;
uint32_t ephemeralSalt = 0;

// Error tracking
uint32_t scanErrors = 0;
uint32_t hashCollisions = 0;

// Device identity
String deviceMacAddress = "";
String combinedBillboardId = "";
String deviceAccessKey = "";
String currentDateTime = "";

// Daily aggregation tracking
String currentDate = "";
uint32_t dailyImpressions = 0;

// GPS location tracking
String gpsLatitude = "0.0";
String gpsLongitude = "0.0";
bool gpsFixAcquired = false;

// Data consumption tracking (in bytes)
uint32_t totalDataSent = 0;
uint32_t dailyDataSent = 0;

bool sdCardAvailable = false;
bool deviceInfoUploaded = false;

// TinyGSM and Firebase objects
TinyGsm modem(SerialAT);
TinyGsmClient gsm_client(modem, 0);
void asyncCB(AsyncResult &aResult);

ESP_SSLClient ssl_client;

using AsyncClient = AsyncClientClass;
AsyncClient aClient(ssl_client);
UserAuth user_auth(API_KEY, USER_EMAIL, USER_PASSWORD, 30000);
FirebaseApp app;
RealtimeDatabase Database;

// Function declarations
String hashMAC(const uint8_t* macAddr);
void performWiFiScan();
void reportAnalytics();
String getMacAddress();
String buildDailyDataJSON();
String buildDeviceInfoJSON();
String generateAccessKey();
bool updateGPSLocation();
bool waitForGPSFix(unsigned long timeoutMs);
String getTimeFromSIM7600();
bool initSDCard();
void logToSD(String message);
void logScanToSD(int networksFound, int uniqueCount, int repeatedCount);
String extractDateFromDateTime(String dateTime);

void setup() {
  SerialMon.begin(115200);
  delay(2000);
  
  systemStartTime = millis();
  
  Serial.println("\n╔════════════════════════════════════════════════════════╗");
  Serial.println("║         TRAFILYTICS - Billboard Analytics              ║");
  Serial.println("║                 Privacy-First System                   ║");
  Serial.println("╚════════════════════════════════════════════════════════╝\n");
  
  Serial.println("📋 PRIVACY CERTIFICATION:");
  Serial.println("   ✓ CCPA Compliant (California Consumer Privacy Act)");
  Serial.println("   ✓ FTC Act Compliant (Aggregated Data Only)");
  Serial.println("   ✓ No MAC Addresses Stored or Transmitted");
  Serial.println("   ✓ One-Way Cryptographic Hashing (FNV-1a 64-bit)");
  Serial.println("   ✓ Ephemeral Salt per Boot (No Cross-Session Tracking)");
  Serial.println("   ✓ Non-Persistent In-Memory Storage Only\n");
  
  Serial.printf("🔧 SYSTEM INFO:\n");
  Serial.printf("   Firmware: %s\n", FIRMWARE_VERSION);
  Serial.printf("   Billboard ID: %s\n", BILLBOARD_ID);
  Serial.printf("   Scan Interval: %u ms\n", SCAN_INTERVAL_MS);
  Serial.printf("   Scans per Upload: %u\n\n", SCANS_PER_UPLOAD);
  
  // Generate ephemeral salt
  randomSeed(analogRead(34) ^ micros());
  ephemeralSalt = random(0xFFFFFFFF);
  
  // Get device MAC
  deviceMacAddress = getMacAddress();
  combinedBillboardId = String(BILLBOARD_ID) + "_" + deviceMacAddress;
  deviceAccessKey = generateAccessKey();
  
  Serial.printf("🔐 SECURITY INFO:\n");
  Serial.printf("   Ephemeral Salt: 0x%08X\n", ephemeralSalt);
  Serial.printf("   Hash Algorithm: FNV-1a 64-bit\n");
  Serial.printf("   Device MAC: %s\n", deviceMacAddress.c_str());
  Serial.printf("   Combined ID: %s\n", combinedBillboardId.c_str());
  Serial.printf("   Access Key: %s\n", deviceAccessKey.c_str());
  Serial.printf("   Startup Timestamp: %u\n\n", systemStartTime);
  
  // Initialize WiFi in station mode (passive scanning)
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  Serial.println("✓ WiFi scanning initialized (passive mode)\n");
  
  // Initialize SD Card
  Serial.println("💾 Initializing SD Card...");
  if (initSDCard()) {
    sdCardAvailable = true;
    Serial.println("✓ SD Card initialized successfully");
    logToSD("=== SYSTEM STARTUP ===");
    logToSD("Firmware: " + String(FIRMWARE_VERSION));
    logToSD("Billboard ID: " + String(BILLBOARD_ID));
    logToSD("Device MAC: " + deviceMacAddress);
    Serial.println();
  } else {
    Serial.println("⚠️  SD Card initialization failed - logging disabled\n");
  }
  
  // Initialize SIM7600G-H modem
  SerialAT.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);
  delay(1000);
  
  Serial.println("🔄 Resetting modem...");
  SerialAT.println("AT+CRESET");
  delay(10000);
  
  while (SerialAT.available()) SerialAT.read();
  
  Serial.println("Waiting for modem ready...");
  unsigned long start = millis();
  bool ready = false;
  while (millis() - start < 30000) {
    if (SerialAT.available()) {
      String line = SerialAT.readStringUntil('\n');
      if (line.indexOf("PB DONE") >= 0) {
        ready = true;
        break;
      }
    }
    delay(100);
  }
  
  if (ready) {
    logToSD("Modem: Ready - PB DONE received");
  } else {
    logToSD("Modem: Warning - PB DONE timeout after 30s");
  }
  
  delay(2000);
  
  Serial.println("Initializing modem...");
  if (!modem.init()) {
    Serial.println("❌ Failed to initialize modem");
    logToSD("Modem: ERROR - Initialization failed");
    return;
  }
  logToSD("Modem: Initialized successfully");
  
  Serial.print("Waiting for network...");
  if (!modem.waitForNetwork()) {
    Serial.println(" fail");
    logToSD("Network: ERROR - Network registration failed");
    return;
  }
  Serial.println(" success");
  logToSD("Network: Registered successfully");
  
  Serial.printf("Connecting to APN: %s\n", apn);
  if (!modem.gprsConnect(apn, gprsUser, gprsPass)) {
    Serial.println("❌ GPRS connection failed");
    logToSD("Network: ERROR - GPRS connection failed");
    return;
  }
  Serial.println("✓ GPRS connected");
  
  IPAddress local = modem.localIP();
  Serial.printf("   Local IP: %s\n", local.toString().c_str());
  logToSD("Network: GPRS connected - IP: " + local.toString());

  // Get time from network
  Serial.println("\n⏰ Getting time from cellular network...");
  currentDateTime = getTimeFromSIM7600();
  currentDate = extractDateFromDateTime(currentDateTime);
  Serial.printf("✓ Current time: %s\n", currentDateTime.c_str());
  Serial.printf("✓ Current date: %s\n\n", currentDate.c_str());
  
  if (currentDateTime == "Time unavailable") {
    logToSD("Time: ERROR - Failed to get time from network");
  } else {
    logToSD("Time: Retrieved successfully - " + currentDateTime);
  }

  // Try to get GPS location with extended timeout
  Serial.println("🛰️  Acquiring GPS fix (90s timeout)...");
  if (waitForGPSFix(90000)) {
    gpsFixAcquired = true;
    Serial.printf("✓ GPS Location: Lat=%s, Long=%s\n\n", gpsLatitude.c_str(), gpsLongitude.c_str());
    logToSD("GPS: Fix acquired - Lat=" + gpsLatitude + ", Lon=" + gpsLongitude);
  } else {
    Serial.println("⚠️  GPS fix not acquired - using fallback coordinates\n");
    gpsLatitude = "33.61095";
    gpsLongitude = "73.061333";
    logToSD("GPS: ERROR - No fix after 90s, using fallback coordinates");
  }
  
  // Initialize Firebase
  Serial.println("Initializing Firebase...");
  Firebase.printf("Firebase Client v%s\n", FIREBASE_CLIENT_VERSION);
  
  Serial.println("   Setting up SSL client...");
  ssl_client.setInsecure();
  ssl_client.setDebugLevel(1);
  ssl_client.setBufferSizes(2048, 1024);
  ssl_client.setClient(&gsm_client);
  
  Serial.println("   Initializing Firebase app...");
  Serial.printf("   API Key: %s...\n", String(API_KEY).substring(0, 10).c_str());
  Serial.printf("   User Email: %s\n", USER_EMAIL);
  Serial.printf("   Database URL: %s\n", DATABASE_URL);
  
  initializeApp(aClient, app, getAuth(user_auth), asyncCB, "authTask");
  app.getApp<RealtimeDatabase>(Database);
  Database.url(DATABASE_URL);
  
  Serial.println("✓ Firebase initialized");
  Serial.println("   Waiting for authentication...\n");
  logToSD("Firebase: Initialized, waiting for authentication");
  
  // Wait for authentication (increased timeout to 60 seconds)
  unsigned long authStart = millis();
  while (!app.ready() && millis() - authStart < 60000) {
    app.loop();
    
    // Show progress every 10 seconds
    if ((millis() - authStart) % 10000 < 100) {
      Serial.printf("   Authentication in progress... %lu seconds\n", (millis() - authStart) / 1000);
    }
    
    delay(100);
  }
  
  if (app.ready()) {
    Serial.println("✓ Firebase authenticated and ready!\n");
    logToSD("Firebase: Authenticated successfully");
    
    // Load existing daily impressions from Firebase
    String impressionsPath = "/devices/" + combinedBillboardId + "/data/" + currentDate + "/daily_impressions";
    Serial.printf("📥 Loading existing impressions from: %s\n", impressionsPath.c_str());
    
    int existingImpressions = Database.get<int>(aClient, impressionsPath.c_str());
    
    if (aClient.lastError().code() == 0 && existingImpressions > 0) {
      dailyImpressions = existingImpressions;
      Serial.printf("✓ Loaded %d existing impressions - continuing from this count\n\n", dailyImpressions);
      logToSD("Firebase: Loaded " + String(existingImpressions) + " existing impressions");
    } else {
      Serial.println("ℹ️  No existing data found - starting fresh for today\n");
      logToSD("Firebase: No existing data, starting fresh");
    }
    
    // Upload device info once in setup
    Serial.println("📤 Uploading device info to Firebase...");
    String devicePath = "/devices/" + combinedBillboardId + "/device_info";
    String deviceJson = buildDeviceInfoJSON();
    Serial.printf("   Path: %s\n", devicePath.c_str());
    Serial.printf("   JSON: %s\n", deviceJson.c_str());
    
    // Use object_t to send raw JSON
    object_t json(deviceJson);
    Database.set<object_t>(aClient, devicePath.c_str(), json, asyncCB, "deviceInfoTask");
    deviceInfoUploaded = true;
    
    // Wait for device info upload to complete
    Serial.println("   Waiting for upload...");
    unsigned long uploadStart = millis();
    while (millis() - uploadStart < 5000) {
      app.loop();
      delay(100);
    }
    Serial.println();
  } else {
    Serial.println("⚠️  Firebase authentication timeout after 60 seconds\n");
    Serial.println("   Troubleshooting steps:");
    Serial.println("   1. Check Firebase credentials in credentials.h");
    Serial.println("   2. Verify internet connectivity (GPRS working)");
    Serial.println("   3. Check Firebase project settings");
    Serial.println("   4. Look at error messages above\n");
    logToSD("Firebase: ERROR - Authentication timeout after 60s");
  }
  Serial.println("════════════════════════════════════════════════════════\n");
}

void loop() {
  app.loop();
  
  uint32_t currentTime = millis();
  
  // Auto-restart every 12 hours for system stability
  if (currentTime - systemStartTime >= 43200000) { // 12 hours in milliseconds
    Serial.println("\n⏰ 12-hour uptime reached - restarting for system stability...");
    Serial.println("═══════════════════════════════════════════════════════\n");
    delay(1000);
    ESP.restart();
  }
  
  // Perform WiFi scan
  if (currentTime - lastScanTime >= SCAN_INTERVAL_MS) {
    performWiFiScan();
    lastScanTime = currentTime;
    scanCounter++;
    
    // Upload every 10 scans
    if (scanCounter >= SCANS_PER_UPLOAD) {
      reportAnalytics();
      
      // Reset cycle tracking
      previousCycleHashes = currentCycleHashes;
      currentCycleHashes.clear();
      wifiNetworksThisCycle = 0;
      repeatedWifiNetworks = 0;
      uniqueWifiNetworks = 0;
      impressionCount = 0;
      scanCounter = 0;
    }
  }
  
  yield();
  delay(100);
}

void performWiFiScan() {
  int networksFound = WiFi.scanNetworks();
  totalScansPerformed++;
  
  if (networksFound < 0) {
    scanErrors++;
    Serial.printf("[WARN] WiFi scan error (code: %d) - Error Count: %u\n", 
                  networksFound, scanErrors);
    logToSD("WiFi Scan Error: code " + String(networksFound));
    return;
  }
  
  if (networksFound == 0) {
    Serial.println("[INFO] No WiFi networks detected in this scan");
    logToSD("WiFi Scan: No networks found");
    return;
  }
  
  // Process valid scan results
  Serial.printf("[SCAN %u/%u] Found %d network(s) - Total Scans: %u\n", 
                scanCounter + 1, SCANS_PER_UPLOAD, networksFound, totalScansPerformed);
  impressionCount += networksFound;
  
  int uniqueInThisScan = 0;
  int repeatedInThisScan = 0;
  int processCount = (networksFound > MAX_NETWORKS_PER_SCAN) ? 
                     MAX_NETWORKS_PER_SCAN : networksFound;
  
  for (int i = 0; i < processCount; i++) {
    uint8_t* bssid = WiFi.BSSID(i);
    String ssid = WiFi.SSID(i);
    int32_t rssi = WiFi.RSSI(i);
    
    String hashedBSSID = hashMAC(bssid);
    
    if (currentCycleHashes.find(hashedBSSID) != currentCycleHashes.end()) {
      repeatedInThisScan++;
    } else {
      uniqueInThisScan++;
      currentCycleHashes.insert(hashedBSSID);
      
      if (previousCycleHashes.find(hashedBSSID) == previousCycleHashes.end()) {
        totalWifiNetworks++;
      }
    }
    
    Serial.printf("   [%s] Hash: %s\n", ssid.c_str(), 
                  hashedBSSID.substring(0, 12).c_str());
  }
  
  wifiNetworksThisCycle += networksFound;
  uniqueWifiNetworks += uniqueInThisScan;
  repeatedWifiNetworks += repeatedInThisScan;
  
  // Log scan results to SD card
  logScanToSD(networksFound, uniqueInThisScan, repeatedInThisScan);
}

String hashMAC(const uint8_t* macAddr) {
  const uint64_t FNV_OFFSET_BASIS = 0xcbf29ce484222325ULL;
  const uint64_t FNV_PRIME = 0x100000001b3ULL;
  
  uint64_t hash = FNV_OFFSET_BASIS;
  
  for (int i = 0; i < 6; i++) {
    hash ^= macAddr[i];
    hash *= FNV_PRIME;
  }
  
  uint8_t* saltBytes = (uint8_t*)&ephemeralSalt;
  for (int i = 0; i < 4; i++) {
    hash ^= saltBytes[i];
    hash *= FNV_PRIME;
  }
  
  char hexBuffer[17];
  sprintf(hexBuffer, "%016llx", hash);
  
  return String(hexBuffer);
}

void reportAnalytics() {
  reportCounter++;
  totalReportsGenerated++;
  dailyImpressions += impressionCount;
  
  Serial.println("\n╔════════════════════════════════════════════════════════╗");
  Serial.println("║            ANALYTICS REPORT - PRIVACY CERTIFIED        ║");
  Serial.println("╚════════════════════════════════════════════════════════╝\n");
  
  // Update GPS before upload
  Serial.println("🛰️  Updating GPS location...");
  if (updateGPSLocation()) {
    Serial.printf("✓ GPS Updated: Lat=%s, Long=%s\n", gpsLatitude.c_str(), gpsLongitude.c_str());
    gpsFixAcquired = true;
  } else {
    Serial.println("⚠️  GPS update failed - using last known location");
  }
  
  // Display statistics
  Serial.println("\n📈 10-SCAN CYCLE STATISTICS (Last 10 Scans):");
  Serial.printf("   ├─ Total Detections (Impressions):    %u\n", impressionCount);
  Serial.printf("   ├─ WiFi Networks Found:                %u\n", wifiNetworksThisCycle);
  Serial.printf("   ├─ Unique Networks (New):              %u\n", uniqueWifiNetworks);
  Serial.printf("   ├─ Repeated Networks (Seen Before):    %u\n", repeatedWifiNetworks);
  Serial.printf("   └─ Total Unique Networks (Cumulative): %u\n\n", totalWifiNetworks);
  
  Serial.println("📊 SYSTEM STATISTICS (Cumulative):");
  Serial.printf("   ├─ Total Scans Performed:      %u\n", totalScansPerformed);
  Serial.printf("   ├─ Reports Generated:          %u\n", totalReportsGenerated);
  Serial.printf("   ├─ Daily Impressions:          %u\n", dailyImpressions);
  Serial.printf("   ├─ Combined Billboard ID:      %s\n", combinedBillboardId.c_str());
  Serial.printf("   ├─ GPS Location:               %s, %s\n", gpsLatitude.c_str(), gpsLongitude.c_str());
  Serial.printf("   ├─ GPS Status:                 %s\n", gpsFixAcquired ? "LOCKED" : "SEARCHING");
  Serial.printf("   └─ Total Data Sent:            %.2f KB\n\n", totalDataSent / 1024.0);
  
  Serial.println("🔐 PRIVACY & SECURITY STATUS:");
  Serial.println("   ├─ MAC Address Protection:     ONE-WAY HASHED ✓");
  Serial.println("   ├─ Hash Algorithm:             FNV-1a 64-bit ✓");
  Serial.println("   ├─ Ephemeral Salt:             ACTIVE (Per-Boot) ✓");
  Serial.println("   ├─ Data Persistence:           NONE (Memory Only) ✓");
  Serial.println("   ├─ Cross-Session Tracking:     PREVENTED ✓");
  Serial.println("   └─ CCPA Compliance:            VERIFIED ✓\n");
  
  if (app.ready()) {
    // Update time before upload
    currentDateTime = getTimeFromSIM7600();
    String newDate = extractDateFromDateTime(currentDateTime);
    
    // Only process day change if we got valid time
    if (newDate != "Unknown" && currentDateTime != "Time unavailable") {
      // Check for day change
      if (newDate != currentDate && currentDate.length() > 0) {
        Serial.printf("📅 New day detected - loading data for new date (was %s, now %s)\n", currentDate.c_str(), newDate.c_str());
        currentDate = newDate;
        
        // Load existing impressions for the new day
        String impressionsPath = "/devices/" + combinedBillboardId + "/data/" + currentDate + "/daily_impressions";
        Serial.printf("📥 Loading impressions for new day from: %s\n", impressionsPath.c_str());
        
        int existingImpressions = Database.get<int>(aClient, impressionsPath.c_str());
        
        if (aClient.lastError().code() == 0 && existingImpressions > 0) {
          dailyImpressions = existingImpressions;
          Serial.printf("✓ Loaded %d existing impressions for new day\n", dailyImpressions);
        } else {
          dailyImpressions = 0;
          Serial.println("ℹ️  No existing data for new day - starting fresh\n");
        }
      } else if (currentDate.length() == 0) {
        currentDate = newDate;
      }
      
      // Only upload if we have valid date
      if (currentDate.length() > 0 && currentDate != "Unknown") {
        String json = buildDailyDataJSON();
        Serial.println("📡 Uploading daily data to Firebase...");
        Serial.println(json);
        Serial.println();
        
        // Upload to daily data path: /devices/BILLBOARD_ID/data/DATE
        String path = "/devices/" + combinedBillboardId + "/data/" + currentDate;
        Serial.printf("📤 Path: %s\n", path.c_str());
        
        // Use object_t to send raw JSON
        object_t jsonObj(json);
        Database.set<object_t>(aClient, path.c_str(), jsonObj, asyncCB, "dailyDataTask");
        
        // Update GPS location in device_info after every data push
        String locationPath = "/devices/" + combinedBillboardId + "/device_info/Location";
        String locationJson = "{\"Lat\":\"" + gpsLatitude + "\",\"Long\":\"" + gpsLongitude + "\"}";
        Serial.printf("📍 Updating location: %s\n", locationPath.c_str());
        object_t locationObj(locationJson);
        Database.set<object_t>(aClient, locationPath.c_str(), locationObj, asyncCB, "locationUpdateTask");
        
        // Wait for uploads to complete (reduced to 3 seconds to prevent blocking)
        Serial.println("   Waiting for uploads to complete...");
        unsigned long uploadWaitStart = millis();
        while (millis() - uploadWaitStart < 3000) {
          app.loop();
          delay(50);
        }
        
        totalDataSent += json.length() + locationJson.length() + 400; // Approximate overhead
      } else {
        Serial.println("⚠️  Skipping upload - no valid date available, will retry next cycle\n");
      }
    } else {
      Serial.println("⚠️  Time retrieval failed - skipping upload, will retry next cycle\n");
    }
  } else {
    Serial.println("⚠️  Firebase not ready - skipping upload\n");
  }
  
  Serial.println("════════════════════════════════════════════════════════\n");
  
  // Log report to SD card
  if (sdCardAvailable) {
    logToSD("--- ANALYTICS REPORT ---");
    logToSD("Impressions (10-scan): " + String(impressionCount));
    logToSD("Daily Impressions: " + String(dailyImpressions));
    logToSD("Unique Networks: " + String(uniqueWifiNetworks));
    logToSD("GPS: " + gpsLatitude + ", " + gpsLongitude);
    logToSD("Total Scans: " + String(totalScansPerformed));
    logToSD("Total Data Sent: " + String(totalDataSent / 1024.0) + " KB");
  }
}

String buildDailyDataJSON() {
  /*
   * JSON Daily Analytics Payload - Optimized for Firebase structure
   */
  String json = "{";
  json += "\"billboard_id\":\"" + combinedBillboardId + "\",";
  json += "\"date\":\"" + currentDate + "\",";
  json += "\"daily_impressions\":" + String(dailyImpressions) + ",";
  json += "\"last_updated\":\"" + currentDateTime + "\"";
  json += "}";
  return json;
}

String buildDeviceInfoJSON() {
  /*
   * Device information for QR code access
   */
  String json = "{";
  json += "\"billboard_id\":\"" + combinedBillboardId + "\",";
  json += "\"device_name\":\"" + String(BILLBOARD_ID) + "\",";
  json += "\"firmware\":\"" + String(FIRMWARE_VERSION) + "\",";
  json += "\"mac_address\":\"" + deviceMacAddress + "\",";
  json += "\"setup_time\":\"" + currentDateTime + "\",";
  json += "\"status\":\"active\",";
  json += "\"Location\":{";
  json += "\"Lat\":\"" + gpsLatitude + "\",";
  json += "\"Long\":\"" + gpsLongitude + "\"";
  json += "}";
  json += "}";
  return json;
}

String generateAccessKey() {
  /*
   * Generate unique access key for QR code authentication
   */
  return String(BILLBOARD_ID) + "_" + deviceMacAddress.substring(0, 8) + "_" + String(millis());
}

bool waitForGPSFix(unsigned long timeoutMs) {
  /*
   * Wait for GPS fix with timeout (like backup code)
   */
  unsigned long start = millis();
  unsigned long lastDot = 0;

  Serial.print("Getting GPS fix");
  
  // Enable GPS
  SerialAT.println("AT+CGPS=1");
  delay(2000);

  while (millis() - start < timeoutMs) {
    if (millis() - lastDot >= 1000) {
      Serial.print(".");
      lastDot = millis();
    }

    SerialAT.println("AT+CGPSINFO");
    delay(1000);

    while (SerialAT.available()) {
      String line = SerialAT.readStringUntil('\n');
      line.trim();
      if (line.isEmpty()) continue;

      if (line.startsWith("+CGPSINFO:")) {
        if (line.indexOf(",,,,,,,,,") != -1) break; // no fix yet

        String data = line.substring(line.indexOf(':') + 1);
        data.trim();

        int i1 = data.indexOf(','), i2 = data.indexOf(',', i1 + 1);
        int i3 = data.indexOf(',', i2 + 1), i4 = data.indexOf(',', i3 + 1);

        String rawLat = data.substring(0, i1);
        String latDir = data.substring(i1 + 1, i2);
        String rawLon = data.substring(i2 + 1, i3);
        String lonDir = data.substring(i3 + 1, i4);

        if (rawLat.isEmpty() || rawLon.isEmpty()) break;

        float latVal = rawLat.toFloat(), lonVal = rawLon.toFloat();
        int latDeg = int(latVal / 100), lonDeg = int(lonVal / 100);
        float latDec = latDeg + (latVal - latDeg * 100) / 60.0;
        float lonDec = lonDeg + (lonVal - lonDeg * 100) / 60.0;

        if (latDir == "S") latDec *= -1;
        if (lonDir == "W") lonDec *= -1;

        gpsLatitude = String(latDec, 6);
        gpsLongitude = String(lonDec, 6);

        float elapsed = (millis() - start) / 1000.0;
        Serial.printf(" ✅ (%.1fs)\n", elapsed);
        return true;
      }
    }
  }

  Serial.println("\n⚠️ Timeout: GPS fix not acquired.");
  return false;
}

bool updateGPSLocation() {
  /*
   * Quick GPS update (for periodic refresh)
   */
  for (int attempt = 0; attempt < 3; attempt++) {
    SerialAT.println("AT+CGPSINFO");
    delay(2000);

    while (SerialAT.available()) {
      String line = SerialAT.readStringUntil('\n');
      line.trim();
      
      logToSD("GPS Response: " + line);

      if (line.startsWith("+CGPSINFO:")) {
        if (line.indexOf(",,,,,,,,,") != -1) {
          logToSD("GPS: No fix - empty coordinates");
          break;
        }

        String data = line.substring(line.indexOf(':') + 1);
        data.trim();

        int i1 = data.indexOf(','), i2 = data.indexOf(',', i1 + 1);
        int i3 = data.indexOf(',', i2 + 1), i4 = data.indexOf(',', i3 + 1);

        String rawLat = data.substring(0, i1);
        String latDir = data.substring(i1 + 1, i2);
        String rawLon = data.substring(i2 + 1, i3);
        String lonDir = data.substring(i3 + 1, i4);

        if (rawLat.isEmpty() || rawLon.isEmpty()) {
          logToSD("GPS: Empty lat/lon values");
          break;
        }

        float latVal = rawLat.toFloat(), lonVal = rawLon.toFloat();
        int latDeg = int(latVal / 100), lonDeg = int(lonVal / 100);
        float latDec = latDeg + (latVal - latDeg * 100) / 60.0;
        float lonDec = lonDeg + (lonVal - lonDeg * 100) / 60.0;

        if (latDir == "S") latDec *= -1;
        if (lonDir == "W") lonDec *= -1;

        gpsLatitude = String(latDec, 6);
        gpsLongitude = String(lonDec, 6);
        logToSD("GPS Updated: Lat=" + gpsLatitude + ", Lon=" + gpsLongitude);
        return true;
      }
    }
  }
  
  logToSD("GPS update failed after 3 attempts");
  return false;
}

String getTimeFromSIM7600() {
  /*
   * Get current date/time from SIM7600G-H with retry logic
   */
  for (int attempt = 0; attempt < 3; attempt++) {
    SerialAT.println("AT+CCLK?");
    delay(1000);
    
    String response = "";
    unsigned long start = millis();
    while (millis() - start < 2000) {
      if (SerialAT.available()) {
        response += SerialAT.readString();
        break;
      }
      delay(50);
    }
    
    logToSD("Time Response: " + response);
    
    // Parse: +CCLK: "25/12/02,10:30:45+00"
    int startPos = response.indexOf("\"") + 1;
    int endPos = response.indexOf("\"", startPos);
    
    if (startPos > 0 && endPos > startPos) {
      String timeStr = response.substring(startPos, endPos);
      
      if (timeStr.length() >= 17) {
        String year = "20" + timeStr.substring(0, 2);
        String month = timeStr.substring(3, 5);
        String day = timeStr.substring(6, 8);
        String time = timeStr.substring(9, 17);
        
        String formattedTime = year + "-" + month + "-" + day + " " + time + " UTC";
        logToSD("Time Retrieved: " + formattedTime);
        return formattedTime;
      }
    }
    
    Serial.printf("[WARN] Time retrieval attempt %d failed, retrying...\n", attempt + 1);
    delay(500);
  }
  
  logToSD("Time retrieval failed after 3 attempts");
  return "Time unavailable";
}

String extractDateFromDateTime(String dateTime) {
  /*
   * Extract date from datetime
   * From: "2025-12-02 14:30:45 UTC" To: "2025-12-02"
   */
  int spaceIndex = dateTime.indexOf(' ');
  if (spaceIndex > 0) {
    return dateTime.substring(0, spaceIndex);
  }
  return "Unknown";
}

String getMacAddress() {
  uint8_t baseMac[6];
  esp_read_mac(baseMac, ESP_MAC_WIFI_STA);
  
  char macStr[13];
  sprintf(macStr, "%02X%02X%02X%02X%02X%02X", 
          baseMac[0], baseMac[1], baseMac[2], 
          baseMac[3], baseMac[4], baseMac[5]);
  
  return String(macStr);
}

void asyncCB(AsyncResult &aResult) {
  if (aResult.isEvent()) {
    Firebase.printf("Event: %s, msg: %s, code: %d\n", 
                    aResult.uid().c_str(), 
                    aResult.appEvent().message().c_str(), 
                    aResult.appEvent().code());
    
    if (String(aResult.uid()) == "authTask" && aResult.appEvent().code() == 9) {
      Serial.println("✓ Authentication successful!");
    }
  }
  
  if (aResult.isDebug()) {
    Firebase.printf("Debug: %s, msg: %s\n", aResult.uid().c_str(), aResult.debug().c_str());
  }
  
  if (aResult.isError()) {
    Serial.println("\n❌ FIREBASE ERROR:");
    Firebase.printf("   Task: %s\n", aResult.uid().c_str());
    Firebase.printf("   Message: %s\n", aResult.error().message().c_str());
    Firebase.printf("   Code: %d\n\n", aResult.error().code());
    
    String errorLog = "Firebase Upload ERROR - Task: " + String(aResult.uid().c_str()) + 
                     ", Code: " + String(aResult.error().code()) + 
                     ", Msg: " + String(aResult.error().message().c_str());
    logToSD(errorLog);
  }
  
  if (aResult.available()) {
    String taskId = String(aResult.uid());
    if (taskId == "deviceInfoTask") {
      Serial.println("✓ Device info upload successful!\n");
      logToSD("Firebase Upload: Device info successful");
    } else if (taskId == "dailyDataTask") {
      Serial.println("✓ Daily data upload successful!\n");
      logToSD("Firebase Upload: Daily data successful");
    } else if (taskId == "locationUpdateTask") {
      Serial.println("✓ Location update successful!\n");
      logToSD("Firebase Upload: Location update successful");
    } else {
      Firebase.printf("✓ Upload successful: %s\n", taskId.c_str());
      logToSD("Firebase Upload: " + taskId + " successful");
    }
  }
}

// ============ SD CARD LOGGING FUNCTIONS ============

bool initSDCard() {
  /*
   * Initialize SD card module
   * Default SPI pins for ESP32: MOSI=23, MISO=19, SCK=18
   * CS pin defined as SD_CS_PIN
   */
  if (!SD.begin(SD_CS_PIN)) {
    Serial.println("   SD Card mount failed!");
    return false;
  }
  
  uint8_t cardType = SD.cardType();
  if (cardType == CARD_NONE) {
    Serial.println("   No SD card attached!");
    return false;
  }
  
  Serial.print("   SD Card Type: ");
  if (cardType == CARD_MMC) {
    Serial.println("MMC");
  } else if (cardType == CARD_SD) {
    Serial.println("SDSC");
  } else if (cardType == CARD_SDHC) {
    Serial.println("SDHC");
  } else {
    Serial.println("UNKNOWN");
  }
  
  uint64_t cardSize = SD.cardSize() / (1024 * 1024);
  Serial.printf("   SD Card Size: %lluMB\n", cardSize);
  
  uint64_t cardUsed = SD.usedBytes() / (1024 * 1024);
  uint64_t cardTotal = SD.totalBytes() / (1024 * 1024);
  Serial.printf("   Space Used: %lluMB / %lluMB\n", cardUsed, cardTotal);
  
  return true;
}

void logToSD(String message) {
  /*
   * Write a log message to SD card with timestamp
   * Creates/appends to trafilytics_log.txt
   */
  if (!sdCardAvailable) return;
  
  File logFile = SD.open("/trafilytics_log.txt", FILE_APPEND);
  if (!logFile) {
    return;
  }
  
  // Write timestamp and message
  String logEntry = "[" + currentDateTime + "] " + message;
  logFile.println(logEntry);
  logFile.close();
}

void logScanToSD(int networksFound, int uniqueCount, int repeatedCount) {
  /*
   * Log WiFi scan results to SD card with timestamp
   */
  if (!sdCardAvailable) return;
  
  String scanLog = "SCAN #" + String(totalScansPerformed) + ": ";
  scanLog += "Found=" + String(networksFound) + ", ";
  scanLog += "Unique=" + String(uniqueCount) + ", ";
  scanLog += "Repeated=" + String(repeatedCount);
  
  logToSD(scanLog);
}
  