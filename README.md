# Nova — Secure LoRa Mesh IoT System

A complete, production-grade wireless sensor network built from scratch across **three custom firmware nodes** — a battery-powered field transmitter, a mesh repeater, and a network controller with Ethernet/MQTT backhaul. All traffic is AES-128 encrypted and MAC-authenticated end-to-end.

---

## System Architecture

![Nova System Architecture](nova_system_diagram.png)

## System Overview

```
                           ┌──────────────────────────────────────────┐
                           │            MQTT Broker / Cloud           │
                           │        (192.168.1.50:1883)               │
                           └────────────────┬─────────────────────────┘
                                            │ Ethernet (W5500)
                                            │
                           ┌────────────────▼─────────────────────────┐
                           │          NC1020 — Network Controller     │
                           │          ESP32-S3 + ESP-IDF 6.0          │
                           │                                          │
                           │  • W5500 Ethernet (SPI, 20 MHz)          │
                           │  • MQTT publish (sensor data, alerts)    │
                           │  • Device whitelist & registry           │
                           │  • SSD1306 OLED display (I2C)            │
                           │  • Buzzer alerts (low battery, timeout)  │
                           │  • Heartbeat timeout monitoring          │
                           │  • Network auto-recovery                 │
                           │  • Watchdog-supervised tasks              │
                           └────────────────▲─────────────────────────┘
                                            │ LoRa 915 MHz
                                            │ AES-128 Encrypted
                                            │
                           ┌────────────────┴─────────────────────────┐
                           │          XR1050 — LoRa Repeater          │
                           │          ESP32-C3 (RISC-V) + ESP-IDF 6.0 │
                           │                                          │
                           │  • Decrypt → Verify MAC → Dedup → Relay  │
                           │  • Sliding-window dedup cache (50 pkts)  │
                           │  • Battery monitoring (ADC + calibration)│
                           │  • Self-reporting heartbeats (15 min)    │
                           │  • 7-pattern LED status state machine    │
                           └────────────────▲─────────────────────────┘
                                            │ LoRa 915 MHz
                                            │ AES-128 Encrypted
                                            │
          ┌─────────────────────────────────┴──────────────────────────────────┐
          │                                                                    │
┌─────────▼──────────┐  ┌─────────▼──────────┐  ┌─────────▼──────────┐
│   TR1050 Sensor #1  │  │   TR1050 Sensor #2  │  │   TR1050 Sensor #N  │
│   STM32L0xx + HAL   │  │   STM32L0xx + HAL   │  │   STM32L0xx + HAL   │
│                     │  │                     │  │                     │
│ • Ultra-low-power   │  │ • Button-triggered  │  │ • Software AES-128  │
│ • STOP mode sleep   │  │ • Battery sensing   │  │ • CBC-MAC auth      │
│ • Wake-on-interrupt │  │ • LED feedback      │  │ • E22 LoRa radio    │
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘
```

## Nodes

### TR1050 — Field Transmitter
**MCU:** STM32L0xx (ARM Cortex-M0+, ultra-low-power) &nbsp;|&nbsp; **Framework:** STM32 HAL &nbsp;|&nbsp; **Toolchain:** STM32CubeIDE

The edge sensor node. Runs on battery and spends most of its life in **STOP mode** drawing microamps. On button press (or external interrupt), it wakes up, reads the battery voltage via ADC, builds an encrypted LoRa packet, transmits it, and goes right back to sleep.

- **Software AES-128** implementation (tiny-AES-C) — the STM32L0 has no hardware crypto, so encryption runs entirely in software
- **CBC-MAC** authentication tag on every packet
- **STOP mode** with low-power regulator — MCU halts, peripherals off, wakes on EXTI
- **E22 power save mode** during sleep — radio enters standby alongside the MCU
- **12-bit ADC** battery voltage measurement with 51K/51K resistive divider
- **Button debounce** with 50ms guard and release-wait logic

### XR1050 — Mesh Repeater
**MCU:** ESP32-C3 (RISC-V, 160 MHz) &nbsp;|&nbsp; **Framework:** ESP-IDF 6.0, FreeRTOS &nbsp;|&nbsp; **Language:** C

The relay node. Sits between the transmitters and the network controller, extending range across the deployment. Receives encrypted packets, verifies their integrity, checks for duplicates, and re-transmits valid traffic.

- **Hardware AES-128** via ESP32-C3's crypto accelerator
- **Packet deduplication** — sliding-window cache (50 entries, 5-minute TTL) prevents relay loops
- **Autonomous heartbeat** — self-reports battery, RSSI, SNR, and status every 15 minutes
- **Calibrated ADC** — continuous DMA mode with hardware curve-fitting calibration
- **4 concurrent FreeRTOS tasks** — UART RX (priority 10), heartbeat, LED status, statistics
- **7-pattern LED state machine** — boot, config, idle, RX, TX, SOS error, low battery

### NC1020 — Network Controller
**MCU:** ESP32-S3 &nbsp;|&nbsp; **Framework:** ESP-IDF 6.0, FreeRTOS &nbsp;|&nbsp; **Language:** C

The brain of the network. Receives all encrypted LoRa traffic, decrypts and validates it, then publishes structured JSON to an **MQTT broker** over wired **Ethernet (W5500)**. Monitors the health of every field device and raises alerts when things go wrong.

- **W5500 Ethernet** — SPI at 20 MHz, full TCP/IP stack via `esp_netif`, DHCP
- **MQTT client** — publishes to 4 topics: `nova/sensor/data`, `nova/sensor/heartbeat`, `nova/nc/status`, `nova/alerts`
- **Device whitelist** — only authorized device IDs are processed; everything else is rejected at the crypto layer
- **Device registry** — tracks last-seen time, counter, battery, RSSI for up to 10 devices
- **Heartbeat timeout monitoring** — if a device goes silent for 20 minutes, triggers buzzer + MQTT alert
- **Network auto-recovery** — background task monitors Ethernet link and MQTT connection, auto-reconnects with W5500 hardware reset if needed
- **SSD1306 OLED display** (I2C, 400 kHz) — for local status readout
- **Buzzer alerts** — audible feedback for low battery and device timeout events
- **Watchdog timer** (30s) — all 5 tasks are WDT-supervised; system reboots on lockup

## Security

All three nodes share a common AES-128 key and use identical packet formats:

| Feature | TR1050 | XR1050 | NC1020 |
|---|---|---|---|
| AES-128 Encryption | Software (tiny-AES-C) | Hardware accelerator | Hardware accelerator |
| CBC-MAC Authentication | ✓ | ✓ (verify + re-compute) | ✓ (verify) |
| Device Whitelisting | — | — | ✓ |
| Replay Protection | — | Dedup cache | Counter tracking |

## Packet Protocol

### Sensor Packet (32 bytes, AES block-aligned)
```c
typedef struct __attribute__((packed)) {
    uint8_t  device_id;      // Source node identifier
    uint8_t  nc_number;      // Network cluster
    uint32_t counter;        // Monotonic sequence number
    uint16_t battery_mv;     // Battery voltage (millivolts)
    uint8_t  status;         // Bit 0: low battery flag
    uint32_t timestamp;      // Uptime (ms)
    uint8_t  mac[4];         // CBC-MAC authentication tag
    uint8_t  padding[15];    // Pad to 32 bytes (2× AES blocks)
} lora_packet_t;
```

### Heartbeat Packet (16 bytes, single AES block)
```c
typedef struct __attribute__((packed)) {
    uint8_t  device_id;
    uint8_t  nc_number;
    uint32_t counter;
    int16_t  rssi;           // Last received RSSI (dBm)
    int8_t   snr;            // Last received SNR (dB)
    uint16_t battery_mv;
    uint8_t  status;
    uint8_t  mac[4];         // CBC-MAC authentication tag
} heartbeat_packet_t;
```

## Radio Configuration

All nodes are configured identically for interoperability:

| Parameter | Value |
|---|---|
| Module | Ebyte E22-900T22D (SX1262) |
| Frequency | 915.125 MHz (Channel 65) |
| TX Power | 22 dBm |
| Air Data Rate | 2.4 kbps |
| UART Baud | 9600 (TR1050: 115200 to host UART) |
| Sub-packet Size | 240 bytes |
| Mode | Transparent |

## Project Structure

```
Nova Firmware/
├── Transmitter/
│   └── TR1050 Transmitter/          # STM32CubeIDE project
│       ├── Core/
│       │   ├── Inc/
│       │   │   ├── main.h           # Pin definitions, GPIO mapping
│       │   │   └── aes.h            # tiny-AES-C header
│       │   └── Src/
│       │       ├── main.c           # Transmitter firmware (710 lines)
│       │       └── aes.c            # Software AES-128 implementation
│       └── Drivers/                 # STM32L0xx HAL drivers
│
├── XR1050/                          # ESP-IDF project (repeater)
│   ├── main/
│   │   └── main.c                   # Repeater firmware (805 lines)
│   ├── CMakeLists.txt
│   └── sdkconfig                    # ESP32-C3 SDK configuration
│
└── NC1020/                          # ESP-IDF project (controller)
    ├── main/
    │   └── main.c                   # Controller firmware (893 lines)
    ├── managed_components/
    │   ├── espressif__mqtt/          # MQTT client library
    │   └── espressif__w5500/         # W5500 Ethernet driver
    ├── CMakeLists.txt
    └── sdkconfig
```

## Building

### TR1050 (STM32)
Open `Transmitter/TR1050 Transmitter/` in **STM32CubeIDE**. Build and flash via ST-Link.

### XR1050 (ESP32-C3)
```bash
cd XR1050
idf.py set-target esp32c3
idf.py build
idf.py -p <PORT> flash monitor
```

### NC1020 (ESP32-S3)
```bash
cd NC1020
idf.py build
idf.py -p <PORT> flash monitor
```

## Configuration

Each node's key parameters are defined at the top of its `main.c`. At minimum, set:

- **`DEVICE_ID`** — unique per node
- **`NC_NUMBER`** — must match across the network cluster
- **`AES_KEY[16]`** — must be identical on all nodes
- **`MQTT_BROKER_URI`** — (NC1020 only) your MQTT broker address

## License

All rights reserved.
