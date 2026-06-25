#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_adc/adc_continuous.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "aes/esp_aes.h"
#include "nvs_flash.h"

// ===================== CONFIGURATION =====================
#define DEVICE_ID 0x02
#define NC_NUMBER 0x01
#define BATTERY_LOW_THRESHOLD 3.3f
#define HEARTBEAT_INTERVAL_MS 900000  // 15 minutes
#define DEDUP_CACHE_SIZE 50
#define PACKET_MAX_AGE_MS 300000      // 5 minutes


// UART Configuration
#define E22_UART_NUM UART_NUM_1
#define E22_UART_TX_PIN 21  // D6
#define E22_UART_RX_PIN 20  // D7
#define E22_UART_BAUD 9600
#define E22_UART_BUF_SIZE 1024

// GPIO Pins
#define E22_M0_PIN 2        // D0
#define E22_M1_PIN 3        // D1
#define E22_AUX_PIN 4       // D2
#define BATTERY_ADC_PIN 0   // A0
#define LED_PIN 10          // Built-in LED

// E22 Commands
#define E22_CMD_READ_CONFIG 0xC1
#define E22_CMD_WRITE_CONFIG 0xC0

// AES Key (MUST match all nodes)
const uint8_t AES_KEY[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x97, 0x46, 0x09, 0xCF, 0x4F, 0x3C
};

static const char *TAG = "XR1050";

// ===================== STRUCTURES =====================
typedef enum {
    E22_MODE_NORMAL = 0,
    E22_MODE_WOR = 1,
    E22_MODE_POWERSAVE = 3,
    E22_MODE_CONFIG = 2
} e22_mode_t;

typedef struct __attribute__((packed)) {
    uint8_t addh;
    uint8_t addl;
    uint8_t netid;
    uint8_t reg0;
    uint8_t reg1;
    uint8_t reg2;
    uint8_t reg3;
    uint8_t crypt_h;
    uint8_t crypt_l;
} e22_config_t;

typedef struct __attribute__((packed)) {
    uint8_t device_id;
    uint8_t nc_number;
    uint32_t counter;
    uint16_t battery_mv;
    uint8_t status;
    uint32_t timestamp;
    uint8_t mac[4];
    uint8_t padding[15];
} lora_packet_t;

typedef struct __attribute__((packed)) {
    uint8_t device_id;
    uint8_t nc_number;
    uint32_t counter;
    int16_t rssi;
    int8_t snr;
    uint16_t battery_mv;
    uint8_t status;
    uint8_t mac[4];
} heartbeat_packet_t;

typedef struct {
    uint64_t packet_id;
    int64_t timestamp;
} dedup_entry_t;

// LED Status Patterns
typedef enum {
    LED_STATUS_BOOTING,          // Fast blink (100ms on/off)
    LED_STATUS_CONFIGURING,      // Double blink pattern
    LED_STATUS_IDLE,             // Slow heartbeat (2s period)
    LED_STATUS_RECEIVING,        // Solid on during RX
    LED_STATUS_FORWARDING,       // Rapid blink during TX
    LED_STATUS_ERROR,            // SOS pattern (... --- ...)
    LED_STATUS_LOW_BATTERY       // Triple blink every 5s
} led_status_t;

// ===================== GLOBAL VARIABLES =====================
static dedup_entry_t dedup_cache[DEDUP_CACHE_SIZE];
static int dedup_index = 0;
static uint32_t heartbeat_counter = 0;
static int64_t last_heartbeat = 0;
static int16_t last_rssi = 0;
static float last_snr = 0;
static uint32_t packets_received = 0;
static uint32_t packets_forwarded = 0;
static uint32_t packets_dropped = 0;
static led_status_t current_led_status = LED_STATUS_BOOTING;
static bool led_override = false;  // For temporary status changes
static adc_continuous_handle_t adc_handle = NULL;
static adc_cali_handle_t adc_cali_handle = NULL;


void adc_init(void)
{
    adc_continuous_handle_cfg_t adc_config = {
        .max_store_buf_size = 1024,
        .conv_frame_size = 100,
    };

    ESP_ERROR_CHECK(adc_continuous_new_handle(&adc_config, &adc_handle));

    adc_continuous_config_t dig_cfg = {
        .sample_freq_hz = 1000,
        .conv_mode = ADC_CONV_SINGLE_UNIT_1,
        .format = ADC_DIGI_OUTPUT_FORMAT_TYPE2,
    };

    adc_digi_pattern_config_t pattern = {
        .atten = ADC_ATTEN_DB_12,
        .channel = ADC_CHANNEL_0,
        .unit = ADC_UNIT_1,
        .bit_width = ADC_BITWIDTH_12,
    };

    dig_cfg.pattern_num = 1;
    dig_cfg.adc_pattern = &pattern;

    ESP_ERROR_CHECK(adc_continuous_config(adc_handle, &dig_cfg));
    ESP_ERROR_CHECK(adc_continuous_start(adc_handle));

    // Calibration
    adc_cali_curve_fitting_config_t cali_config = {
        .unit_id = ADC_UNIT_1,
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_12,
    };

    ESP_ERROR_CHECK(adc_cali_create_scheme_curve_fitting(&cali_config, &adc_cali_handle));
}


// ===================== LED STATUS FUNCTIONS =====================
void led_set_status(led_status_t status) {
    current_led_status = status;
}

void led_blink_pattern(int on_ms, int off_ms, int count) {
    for (int i = 0; i < count; i++) {
        gpio_set_level(LED_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(on_ms));
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(off_ms));
    }
}

void led_sos_pattern(void) {
    // S (... )
    for (int i = 0; i < 3; i++) {
        gpio_set_level(LED_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(200));
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    vTaskDelay(pdMS_TO_TICKS(300));
    
    // O (--- )
    for (int i = 0; i < 3; i++) {
        gpio_set_level(LED_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(600));
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    vTaskDelay(pdMS_TO_TICKS(300));
    
    // S (... )
    for (int i = 0; i < 3; i++) {
        gpio_set_level(LED_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(200));
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

void led_status_task(void* arg) {
    ESP_LOGI(TAG, "LED status task started");
    
    int heartbeat_phase = 0;
    int idle_counter = 0;
    
    while (1) {
        if (led_override) {
            // Don't interfere with manual LED control
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        
        switch (current_led_status) {
            case LED_STATUS_BOOTING:
                // Fast blink: 100ms on, 100ms off
                gpio_set_level(LED_PIN, 1);
                vTaskDelay(pdMS_TO_TICKS(100));
                gpio_set_level(LED_PIN, 0);
                vTaskDelay(pdMS_TO_TICKS(100));
                break;
                
            case LED_STATUS_CONFIGURING:
                // Double blink: ON-OFF-ON-OFF-pause
                led_blink_pattern(150, 150, 2);
                vTaskDelay(pdMS_TO_TICKS(800));
                break;
                
            case LED_STATUS_IDLE:
                // Slow heartbeat: gentle pulse every 2 seconds
                idle_counter++;
                if (idle_counter >= 20) {  // 20 * 100ms = 2s
                    // Fade in
                    gpio_set_level(LED_PIN, 1);
                    vTaskDelay(pdMS_TO_TICKS(100));
                    gpio_set_level(LED_PIN, 0);
                    vTaskDelay(pdMS_TO_TICKS(50));
                    gpio_set_level(LED_PIN, 1);
                    vTaskDelay(pdMS_TO_TICKS(100));
                    gpio_set_level(LED_PIN, 0);
                    idle_counter = 0;
                } else {
                    vTaskDelay(pdMS_TO_TICKS(100));
                }
                break;
                
            case LED_STATUS_RECEIVING:
                // Solid on (controlled by RX handler)
                vTaskDelay(pdMS_TO_TICKS(100));
                break;
                
            case LED_STATUS_FORWARDING:
                // Rapid blink (controlled by forward handler)
                vTaskDelay(pdMS_TO_TICKS(100));
                break;
                
            case LED_STATUS_ERROR:
                // SOS pattern
                led_sos_pattern();
                vTaskDelay(pdMS_TO_TICKS(2000));
                break;
                
            case LED_STATUS_LOW_BATTERY:
                // Triple blink every 5 seconds
                led_blink_pattern(200, 200, 3);
                vTaskDelay(pdMS_TO_TICKS(5000));
                break;
                
            default:
                vTaskDelay(pdMS_TO_TICKS(100));
                break;
        }
    }
}
void e22_set_mode(e22_mode_t mode) {
    switch(mode) {
        case E22_MODE_NORMAL:
            gpio_set_level(E22_M0_PIN, 0);
            gpio_set_level(E22_M1_PIN, 0);
            ESP_LOGI(TAG, "E22 Mode: NORMAL");
            break;
        case E22_MODE_WOR:
            gpio_set_level(E22_M0_PIN, 1);
            gpio_set_level(E22_M1_PIN, 0);
            ESP_LOGI(TAG, "E22 Mode: WOR");
            break;
        case E22_MODE_POWERSAVE:
            gpio_set_level(E22_M0_PIN, 1);
            gpio_set_level(E22_M1_PIN, 1);
            ESP_LOGI(TAG, "E22 Mode: POWER SAVE");
            break;
        case E22_MODE_CONFIG:
            gpio_set_level(E22_M0_PIN, 0);
            gpio_set_level(E22_M1_PIN, 1);
            ESP_LOGI(TAG, "E22 Mode: CONFIG");
            break;
    }
    vTaskDelay(pdMS_TO_TICKS(50));
}

void e22_wait_aux_high(void) {
    int timeout = 2000; // 2 seconds
    while (gpio_get_level(E22_AUX_PIN) == 0 && timeout > 0) {
        vTaskDelay(pdMS_TO_TICKS(1));
        timeout--;
    }
    if (timeout == 0) {
        ESP_LOGW(TAG, "AUX timeout!");
    }
}

void e22_configure(void) {
    e22_config_t config;
    uint8_t cmd_buf[12];
    
    ESP_LOGI(TAG, "Configuring E22 module...");
    led_set_status(LED_STATUS_CONFIGURING);
    
    // Enter config mode
    e22_set_mode(E22_MODE_CONFIG);
    e22_wait_aux_high();
    vTaskDelay(pdMS_TO_TICKS(50));
    
    // Read current config
    cmd_buf[0] = E22_CMD_READ_CONFIG;
    cmd_buf[1] = 0x00;
    cmd_buf[2] = 0x09;
    
    uart_write_bytes(E22_UART_NUM, cmd_buf, 3);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    uint8_t rx_buf[12];
    int len = uart_read_bytes(E22_UART_NUM, rx_buf, 12, pdMS_TO_TICKS(1000));
    
    if (len >= 12 && rx_buf[0] == 0xC1) {
        memcpy(&config, &rx_buf[3], 9);
        ESP_LOGI(TAG, "Config read OK");
    } else {
        memset(&config, 0, sizeof(config));
        ESP_LOGW(TAG, "Config read failed, using defaults");
    }
    
    // Configure for repeater operation
    config.addh = 0x00;
    config.addl = 0x00;
    config.netid = NC_NUMBER;
    config.reg0 = 0x62;  // 9600 baud, 8N1, 2.4kbps air
    config.reg1 = 0x00;  // 240 bytes, 22dBm
    config.reg2 = 0x41;  // Channel 65 = 915.125 MHz
    config.reg3 = 0x00;  // Transparent mode
    config.crypt_h = 0x00;
    config.crypt_l = 0x00;
    
    // Write config
    cmd_buf[0] = E22_CMD_WRITE_CONFIG;
    cmd_buf[1] = 0x00;
    cmd_buf[2] = 0x09;
    memcpy(&cmd_buf[3], &config, 9);
    
    uart_write_bytes(E22_UART_NUM, cmd_buf, 12);
    e22_wait_aux_high();
    vTaskDelay(pdMS_TO_TICKS(100));
    
    ESP_LOGI(TAG, "E22 configuration complete");
    
    // Return to normal mode
    e22_set_mode(E22_MODE_NORMAL);
    vTaskDelay(pdMS_TO_TICKS(50));
    
    // Configuration complete, go to idle
    led_set_status(LED_STATUS_IDLE);
}

// ===================== BATTERY MONITORING =====================
float read_battery_voltage(void)
{
    uint8_t result[100];
    uint32_t ret_len = 0;

    ESP_ERROR_CHECK(adc_continuous_read(adc_handle, result, sizeof(result), &ret_len, 1000));

    adc_digi_output_data_t *p = (adc_digi_output_data_t *)result;

    uint32_t raw = p->type2.data;

    int voltage_mv = 0;
    ESP_ERROR_CHECK(adc_cali_raw_to_voltage(adc_cali_handle, raw, &voltage_mv));

    // Voltage divider 51K / 51K (divide by 2)
    float battery_voltage = (voltage_mv / 1000.0f) * 2.0f;

    return battery_voltage;
}

// ===================== ENCRYPTION =====================
void compute_mac(uint8_t* data, uint16_t len, uint8_t* mac_out) {
    uint8_t temp[16] = {0};
    uint16_t copy_len = (len >= 16) ? 16 : len;
    memcpy(temp, data + len - copy_len, copy_len);
    
    esp_aes_context aes_ctx;
    esp_aes_init(&aes_ctx);
    esp_aes_setkey(&aes_ctx, AES_KEY, 128);
    esp_aes_crypt_ecb(&aes_ctx, ESP_AES_ENCRYPT, temp, temp);
    esp_aes_free(&aes_ctx);
    
    memcpy(mac_out, temp, 4);
}

void encrypt_packet(uint8_t* pkt, size_t len) {
    esp_aes_context aes_ctx;
    esp_aes_init(&aes_ctx);
    esp_aes_setkey(&aes_ctx, AES_KEY, 128);
    
    for (size_t i = 0; i < len; i += 16) {
        esp_aes_crypt_ecb(&aes_ctx, ESP_AES_ENCRYPT, pkt + i, pkt + i);
    }
    
    esp_aes_free(&aes_ctx);
}

void decrypt_packet(uint8_t* pkt, size_t len) {
    esp_aes_context aes_ctx;
    esp_aes_init(&aes_ctx);
    esp_aes_setkey(&aes_ctx, AES_KEY, 128);
    
    for (size_t i = 0; i < len; i += 16) {
        esp_aes_crypt_ecb(&aes_ctx, ESP_AES_DECRYPT, pkt + i, pkt + i);
    }
    
    esp_aes_free(&aes_ctx);
}

bool verify_mac(uint8_t* data, uint16_t len, uint8_t* received_mac) {
    uint8_t computed_mac[4];
    compute_mac(data, len - 4, computed_mac);
    return memcmp(computed_mac, received_mac, 4) == 0;
}

// ===================== DEDUPLICATION =====================
bool is_duplicate_packet(uint8_t device_id, uint32_t counter) {
    uint64_t packet_id = ((uint64_t)device_id << 32) | counter;
    int64_t now = esp_timer_get_time() / 1000; // Convert to ms
    
    // Check cache
    for (int i = 0; i < DEDUP_CACHE_SIZE; i++) {
        if (dedup_cache[i].packet_id == packet_id) {
            ESP_LOGD(TAG, "Duplicate packet detected");
            return true;
        }
    }
    
    // Add to cache
    dedup_cache[dedup_index].packet_id = packet_id;
    dedup_cache[dedup_index].timestamp = now;
    dedup_index = (dedup_index + 1) % DEDUP_CACHE_SIZE;
    
    // Cleanup old entries
    for (int i = 0; i < DEDUP_CACHE_SIZE; i++) {
        if (now - dedup_cache[i].timestamp > PACKET_MAX_AGE_MS) {
            dedup_cache[i].packet_id = 0;
        }
    }
    
    return false;
}

// ===================== PACKET FORWARDING =====================
void forward_packet(uint8_t* data, size_t len) {
    // Temporarily override LED status
    led_override = true;
    
    // Rapid blink during forwarding
    for (int i = 0; i < 3; i++) {
        gpio_set_level(LED_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(50));
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    // Wait for E22 ready
    e22_wait_aux_high();
    
    // Random delay to avoid collisions (50-150ms)
    vTaskDelay(pdMS_TO_TICKS(50));
    
    // LED ON during transmission
    gpio_set_level(LED_PIN, 1);
    
    // Transmit
    int written = uart_write_bytes(E22_UART_NUM, data, len);
    
    if (written == len) {
        packets_forwarded++;
        ESP_LOGI(TAG, "Packet forwarded (%d bytes)", len);
    } else {
        packets_dropped++;
        ESP_LOGE(TAG, "Forward failed (%d/%d bytes)", written, len);
    }
    
    // Wait for transmission complete
    e22_wait_aux_high();
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // LED OFF
    gpio_set_level(LED_PIN, 0);
    
    // Resume normal LED status
    led_override = false;
}

// ===================== HEARTBEAT =====================
void send_heartbeat(void) {
    heartbeat_packet_t hb;
    
    ESP_LOGI(TAG, "Sending heartbeat...");
    
    // Check battery status
    float battery_voltage = read_battery_voltage();
    bool low_battery = (battery_voltage < BATTERY_LOW_THRESHOLD);
    
    if (low_battery && current_led_status != LED_STATUS_LOW_BATTERY) {
        ESP_LOGW(TAG, "LOW BATTERY: %.2fV", battery_voltage);
        led_set_status(LED_STATUS_LOW_BATTERY);
    }
    
    hb.device_id = DEVICE_ID;
    hb.nc_number = NC_NUMBER;
    hb.counter = heartbeat_counter++;
    hb.rssi = last_rssi;
    hb.snr = (int8_t)last_snr;
    hb.battery_mv = (uint16_t)(battery_voltage * 1000);
    hb.status = low_battery ? 0x01 : 0x00;
    
    // Compute MAC
    compute_mac((uint8_t*)&hb, sizeof(hb) - 4, hb.mac);
    
    // Encrypt
    encrypt_packet((uint8_t*)&hb, sizeof(hb));
    
    // Override LED temporarily
    led_override = true;
    
    // Double blink for heartbeat
    gpio_set_level(LED_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level(LED_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level(LED_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level(LED_PIN, 0);
    
    // Wait and transmit
    e22_wait_aux_high();
    uart_write_bytes(E22_UART_NUM, (uint8_t*)&hb, sizeof(hb));
    e22_wait_aux_high();
    
    led_override = false;
    
    last_heartbeat = esp_timer_get_time() / 1000;
    
    ESP_LOGI(TAG, "Heartbeat sent (Battery: %.2fV)", hb.battery_mv / 1000.0f);
}

// ===================== PACKET PROCESSING =====================
void process_received_packet(uint8_t* data, size_t len) {
    packets_received++;
    
    // Briefly indicate reception
    led_override = true;
    gpio_set_level(LED_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(50));
    gpio_set_level(LED_PIN, 0);
    led_override = false;
    
    // Create working copy
    uint8_t decrypted[len];
    memcpy(decrypted, data, len);
    
    // Decrypt
    decrypt_packet(decrypted, len);
    
    // Process based on packet type
    if (len == sizeof(lora_packet_t)) {
        lora_packet_t* pkt = (lora_packet_t*)decrypted;
        
        // Verify MAC
        uint8_t saved_mac[4];
        memcpy(saved_mac, pkt->mac, 4);
        memset(pkt->mac, 0, 4);
        
        if (!verify_mac((uint8_t*)pkt, sizeof(lora_packet_t), saved_mac)) {
            ESP_LOGW(TAG, "MAC verification failed - dropping");
            packets_dropped++;
            return;
        }
        
        // Check for duplicate
        if (is_duplicate_packet(pkt->device_id, pkt->counter)) {
            ESP_LOGD(TAG, "Duplicate packet - dropping");
            packets_dropped++;
            return;
        }
        
        // Valid packet - log and forward
        ESP_LOGI(TAG, "Valid packet: ID=%d CNT=%lu BATT=%dmV",
                 pkt->device_id, pkt->counter, pkt->battery_mv);
        
        // Update RSSI/SNR (simulated - E22 doesn't provide real-time RSSI)
        last_rssi = -80; // Placeholder
        last_snr = 8.0f;  // Placeholder
        
        // Forward packet (using original encrypted data)
        forward_packet(data, sizeof(lora_packet_t));
        
    } else if (len == sizeof(heartbeat_packet_t)) {
        heartbeat_packet_t* hb = (heartbeat_packet_t*)decrypted;
        
        // Verify MAC
        uint8_t saved_mac[4];
        memcpy(saved_mac, hb->mac, 4);
        memset(hb->mac, 0, 4);
        
        if (!verify_mac((uint8_t*)hb, sizeof(heartbeat_packet_t), saved_mac)) {
            packets_dropped++;
            return;
        }
        
        // Check duplicate
        if (!is_duplicate_packet(hb->device_id, hb->counter)) {
            ESP_LOGI(TAG, "Forwarding heartbeat from ID=%d", hb->device_id);
            forward_packet(data, len);
        } else {
            packets_dropped++;
        }
        
    } else {
        ESP_LOGW(TAG, "Unknown packet format (%d bytes) - dropping", len);
        packets_dropped++;
    }
}

// ===================== UART RX TASK =====================
void uart_rx_task(void* arg) {
    uint8_t* rx_buffer = (uint8_t*)malloc(E22_UART_BUF_SIZE);
    
    ESP_LOGI(TAG, "UART RX task started");
    
    while (1) {
        int len = uart_read_bytes(E22_UART_NUM, rx_buffer, E22_UART_BUF_SIZE, 
                                  pdMS_TO_TICKS(1000));
        
        if (len > 0) {
            ESP_LOGI(TAG, "Received %d bytes", len);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, rx_buffer, len, ESP_LOG_DEBUG);
            
            // Process packet
            process_received_packet(rx_buffer, len);
        }
    }
    
    free(rx_buffer);
}

// ===================== HEARTBEAT TASK =====================
void heartbeat_task(void* arg) {
    ESP_LOGI(TAG, "Heartbeat task started");
    
    while (1) {
        int64_t now = esp_timer_get_time() / 1000;
        
        if (now - last_heartbeat >= HEARTBEAT_INTERVAL_MS) {
            send_heartbeat();
        }
        
        vTaskDelay(pdMS_TO_TICKS(10000)); // Check every 10 seconds
    }
}

// ===================== STATS TASK =====================
void stats_task(void* arg) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(60000)); // Every minute
        
        ESP_LOGI(TAG, "=== STATS ===");
        ESP_LOGI(TAG, "Received: %lu", packets_received);
        ESP_LOGI(TAG, "Forwarded: %lu", packets_forwarded);
        ESP_LOGI(TAG, "Dropped: %lu", packets_dropped);
        ESP_LOGI(TAG, "Battery: %.2fV", read_battery_voltage());
    }
}

// ===================== GPIO INIT =====================
void gpio_init(void) {
    // M0, M1, LED as outputs
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << E22_M0_PIN) | (1ULL << E22_M1_PIN) | (1ULL << LED_PIN),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io_conf);
    
    // AUX as input
    io_conf.pin_bit_mask = (1ULL << E22_AUX_PIN);
    io_conf.mode = GPIO_MODE_INPUT;
    gpio_config(&io_conf);
    
    // Initial states
    gpio_set_level(E22_M0_PIN, 0);
    gpio_set_level(E22_M1_PIN, 0);
    gpio_set_level(LED_PIN, 0);
    
    ESP_LOGI(TAG, "GPIO initialized");
}

// ===================== UART INIT =====================
void uart_init(void) {
    uart_config_t uart_config = {
        .baud_rate = E22_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB,
    };
    
    ESP_ERROR_CHECK(uart_driver_install(E22_UART_NUM, E22_UART_BUF_SIZE * 2, 
                                        E22_UART_BUF_SIZE * 2, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(E22_UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(E22_UART_NUM, E22_UART_TX_PIN, E22_UART_RX_PIN,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    
    ESP_LOGI(TAG, "UART initialized (TX:%d RX:%d)", E22_UART_TX_PIN, E22_UART_RX_PIN);
}

// ===================== MAIN =====================
void app_main(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "   Nova XR1050 - LoRa Repeater");
    ESP_LOGI(TAG, "   Device ID: 0x%02X", DEVICE_ID);
    ESP_LOGI(TAG, "   Network: 0x%02X", NC_NUMBER);
    ESP_LOGI(TAG, "========================================");
    
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Initialize peripherals
    gpio_init();
    uart_init();
    adc_init();
    
    // LED boot pattern (fast blink 5 times)
    led_set_status(LED_STATUS_BOOTING);
    for (int i = 0; i < 5; i++) {
        gpio_set_level(LED_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(100));
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // Configure E22 module
    e22_configure();
    
    // Check battery
    float battery = read_battery_voltage();
    ESP_LOGI(TAG, "Battery: %.2fV", battery);
    if (battery < BATTERY_LOW_THRESHOLD) {
        ESP_LOGW(TAG, "Battery LOW!");
        led_set_status(LED_STATUS_LOW_BATTERY);
        vTaskDelay(pdMS_TO_TICKS(2000));  // Show warning
    }
    
    // Initialize dedup cache
    memset(dedup_cache, 0, sizeof(dedup_cache));
    
    ESP_LOGI(TAG, "Starting tasks...");
    
    // Create tasks
    xTaskCreate(led_status_task, "led_status", 2048, NULL, 5, NULL);
    xTaskCreate(uart_rx_task, "uart_rx", 4096, NULL, 10, NULL);
    xTaskCreate(heartbeat_task, "heartbeat", 2048, NULL, 5, NULL);
    xTaskCreate(stats_task, "stats", 2048, NULL, 3, NULL);
    
    // Set to idle status
    vTaskDelay(pdMS_TO_TICKS(1000));
    led_set_status(LED_STATUS_IDLE);
    
    ESP_LOGI(TAG, "Repeater ready - listening for packets...");
}

