#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/i2c.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_task_wdt.h"
#include "aes/esp_aes.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "mqtt_client.h"
#include "esp_eth_phy_w5500.h"
#include "esp_eth_mac_w5500.h"

// ===================== CONFIGURATION =====================
#define DEVICE_ID 0xF0
#define NC_NUMBER 0x01

// UART Configuration (E22-900T22S)
#define E22_UART_NUM UART_NUM_2
#define E22_UART_TX_PIN 17
#define E22_UART_RX_PIN 18
#define E22_UART_BAUD 9600
#define E22_UART_BUF_SIZE 1024

// E22 GPIO Pins
#define E22_M0_PIN 4
#define E22_M1_PIN 5
#define E22_AUX_PIN 6

// W5500 SPI Pins
#define W5500_MOSI_PIN 11
#define W5500_MISO_PIN 13
#define W5500_SCK_PIN 12
#define W5500_CS_PIN 10
#define W5500_INT_PIN 9
#define W5500_RST_PIN 14
#define W5500_SPI_CLOCK_MHZ 20

// I2C Display (SSD1306 OLED)
#define I2C_MASTER_SCL_IO 22
#define I2C_MASTER_SDA_IO 21
#define I2C_MASTER_FREQ_HZ 400000
#define I2C_MASTER_NUM I2C_NUM_0

// Output Pins
#define BUZZER_PIN 15
#define STATUS_LED_PIN 2

// Network Configuration
#define MQTT_BROKER_URI "mqtt://192.168.1.50:1883"
#define MQTT_USERNAME "nova_nc"
#define MQTT_PASSWORD "secure_pass"
#define MQTT_TOPIC_DATA "nova/sensor/data"
#define MQTT_TOPIC_HEARTBEAT "nova/sensor/heartbeat"
#define MQTT_TOPIC_STATUS "nova/nc/status"
#define MQTT_TOPIC_ALERT "nova/alerts"

// Timing
#define WATCHDOG_TIMEOUT_S 30
#define HEARTBEAT_TIMEOUT_MS 1200000  // 20 minutes (15min interval + 5min grace)
#define NETWORK_RECOVERY_INTERVAL_MS 10000
#define DISPLAY_UPDATE_MS 1000

// Whitelist (authorized device IDs)
static const uint8_t WHITELIST[] = {0x01, 0x02, 0x03};
#define WHITELIST_SIZE (sizeof(WHITELIST) / sizeof(WHITELIST[0]))

// AES Key (MUST match all nodes)
const uint8_t AES_KEY[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x97, 0x46, 0x09, 0xCF, 0x4F, 0x3C
};

static const char *TAG = "NC1020";

// ===================== STRUCTURES =====================
typedef enum {
    E22_MODE_NORMAL = 0,
    E22_MODE_WOR = 1,
    E22_MODE_POWERSAVE = 2,
    E22_MODE_CONFIG = 3
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
    uint8_t device_id;
    int64_t last_seen;
    uint32_t last_counter;
    uint16_t last_battery_mv;
    int16_t last_rssi;
    bool is_alive;
} device_status_t;

// ===================== GLOBAL VARIABLES =====================
static spi_device_handle_t w5500_spi;
static esp_eth_handle_t eth_handle = NULL;
static esp_mqtt_client_handle_t mqtt_client = NULL;
static bool eth_connected = false;
static bool mqtt_connected = false;

static uint32_t packets_received = 0;
static uint32_t packets_rejected = 0;
static uint32_t packets_processed = 0;

static device_status_t device_registry[10];
static int device_count = 0;

// Event group for synchronization
static EventGroupHandle_t network_event_group;
#define ETH_CONNECTED_BIT BIT0
#define MQTT_CONNECTED_BIT BIT1

// ===================== E22 FUNCTIONS =====================
void e22_set_mode(e22_mode_t mode) {
    switch(mode) {
        case E22_MODE_NORMAL:
            gpio_set_level(E22_M0_PIN, 0);
            gpio_set_level(E22_M1_PIN, 0);
            break;
        case E22_MODE_WOR:
            gpio_set_level(E22_M0_PIN, 1);
            gpio_set_level(E22_M1_PIN, 0);
            break;
        case E22_MODE_POWERSAVE:
            gpio_set_level(E22_M0_PIN, 0);
            gpio_set_level(E22_M1_PIN, 1);
            break;
        case E22_MODE_CONFIG:
            gpio_set_level(E22_M0_PIN, 1);
            gpio_set_level(E22_M1_PIN, 1);
            break;
    }
    vTaskDelay(pdMS_TO_TICKS(50));
}

void e22_wait_aux_high(void) {
    int timeout = 2000;
    while (gpio_get_level(E22_AUX_PIN) == 0 && timeout > 0) {
        vTaskDelay(pdMS_TO_TICKS(1));
        timeout--;
    }
}

void e22_configure(void) {
    e22_config_t config;
    uint8_t cmd_buf[12];
    
    ESP_LOGI(TAG, "Configuring E22 module...");
    
    e22_set_mode(E22_MODE_CONFIG);
    e22_wait_aux_high();
    vTaskDelay(pdMS_TO_TICKS(50));
    
    cmd_buf[0] = 0xC1;
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
    }
    
    config.addh = 0x00;
    config.addl = 0x00;
    config.netid = NC_NUMBER;
    config.reg0 = 0x62;
    config.reg1 = 0x00;
    config.reg2 = 0x41;
    config.reg3 = 0x00;
    config.crypt_h = 0x00;
    config.crypt_l = 0x00;
    
    cmd_buf[0] = 0xC0;
    cmd_buf[1] = 0x00;
    cmd_buf[2] = 0x09;
    memcpy(&cmd_buf[3], &config, 9);
    
    uart_write_bytes(E22_UART_NUM, cmd_buf, 12);
    e22_wait_aux_high();
    
    ESP_LOGI(TAG, "E22 configuration complete");
    e22_set_mode(E22_MODE_NORMAL);
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

// ===================== DEVICE MANAGEMENT =====================
bool is_whitelisted(uint8_t device_id) {
    for (int i = 0; i < WHITELIST_SIZE; i++) {
        if (WHITELIST[i] == device_id) {
            return true;
        }
    }
    return false;
}

device_status_t* find_device(uint8_t device_id) {
    for (int i = 0; i < device_count; i++) {
        if (device_registry[i].device_id == device_id) {
            return &device_registry[i];
        }
    }
    return NULL;
}

void update_device_status(uint8_t device_id, uint32_t counter, uint16_t battery_mv, int16_t rssi) {
    device_status_t* device = find_device(device_id);
    
    if (device == NULL && device_count < 10) {
        device = &device_registry[device_count++];
        device->device_id = device_id;
        ESP_LOGI(TAG, "New device registered: 0x%02X", device_id);
    }
    
    if (device != NULL) {
        device->last_seen = esp_timer_get_time() / 1000;
        device->last_counter = counter;
        device->last_battery_mv = battery_mv;
        device->last_rssi = rssi;
        device->is_alive = true;
    }
}

// ===================== MQTT FUNCTIONS =====================
void mqtt_publish_data(lora_packet_t* pkt, int16_t rssi) {
    if (!mqtt_connected) {
        ESP_LOGW(TAG, "MQTT not connected, queueing data");
        return;
    }
    
    char json[256];
    snprintf(json, sizeof(json),
        "{\"device_id\":%u,\"nc\":%u,\"counter\":%lu,\"battery_mv\":%u,"
        "\"status\":%u,\"timestamp\":%lu,\"rssi\":%d}",
        pkt->device_id, pkt->nc_number, pkt->counter, pkt->battery_mv,
        pkt->status, pkt->timestamp, rssi);
    
    esp_mqtt_client_publish(mqtt_client, MQTT_TOPIC_DATA, json, 0, 1, 0);
    ESP_LOGI(TAG, "Published: %s", json);
}

void mqtt_publish_heartbeat(heartbeat_packet_t* hb) {
    if (!mqtt_connected) return;
    
    char json[256];
    snprintf(json, sizeof(json),
        "{\"device_id\":%u,\"nc\":%u,\"counter\":%lu,\"rssi\":%d,"
        "\"snr\":%d,\"battery_mv\":%u,\"status\":%u}",
        hb->device_id, hb->nc_number, hb->counter, hb->rssi,
        hb->snr, hb->battery_mv, hb->status);
    
    esp_mqtt_client_publish(mqtt_client, MQTT_TOPIC_HEARTBEAT, json, 0, 1, 0);
}

void mqtt_publish_alert(const char* alert_type, uint8_t device_id, const char* message) {
    if (!mqtt_connected) return;
    
    char json[256];
    snprintf(json, sizeof(json),
        "{\"type\":\"%s\",\"device_id\":%u,\"message\":\"%s\",\"timestamp\":%lld}",
        alert_type, device_id, message, esp_timer_get_time() / 1000);
    esp_mqtt_client_publish(mqtt_client, MQTT_TOPIC_ALERT, json, 0, 1, 0);
    ESP_LOGW(TAG, "ALERT: %s", json);
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, 
                               int32_t event_id, void *event_data) {
    esp_mqtt_event_handle_t event = event_data;
    
    switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT connected");
            mqtt_connected = true;
            xEventGroupSetBits(network_event_group, MQTT_CONNECTED_BIT);
            
            esp_mqtt_client_publish(mqtt_client, MQTT_TOPIC_STATUS, 
                "{\"status\":\"online\",\"device\":\"NC1020\"}", 0, 1, 1);
            break;
            
        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "MQTT disconnected");
            mqtt_connected = false;
            xEventGroupClearBits(network_event_group, MQTT_CONNECTED_BIT);
            break;
            
        case MQTT_EVENT_ERROR:
            ESP_LOGE(TAG, "MQTT error");
            break;
            
        default:
            break;
    }
}

// ===================== W5500 ETHERNET =====================
static void eth_event_handler(void *arg, esp_event_base_t event_base,
                             int32_t event_id, void *event_data) {
    uint8_t mac_addr[6] = {0};
    esp_eth_handle_t eth_handle = *(esp_eth_handle_t *)event_data;

    switch (event_id) {
        case ETHERNET_EVENT_CONNECTED:
            esp_eth_ioctl(eth_handle, ETH_CMD_G_MAC_ADDR, mac_addr);
            ESP_LOGI(TAG, "Ethernet Link Up");
            ESP_LOGI(TAG, "MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                     mac_addr[0], mac_addr[1], mac_addr[2],
                     mac_addr[3], mac_addr[4], mac_addr[5]);
            break;
            
        case ETHERNET_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "Ethernet Link Down");
            eth_connected = false;
            xEventGroupClearBits(network_event_group, ETH_CONNECTED_BIT);
            break;
            
        case ETHERNET_EVENT_START:
            ESP_LOGI(TAG, "Ethernet Started");
            break;
            
        case ETHERNET_EVENT_STOP:
            ESP_LOGI(TAG, "Ethernet Stopped");
            break;
            
        default:
            break;
    }
}

static void got_ip_event_handler(void *arg, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    const esp_netif_ip_info_t *ip_info = &event->ip_info;

    ESP_LOGI(TAG, "Ethernet Got IP: " IPSTR, IP2STR(&ip_info->ip));
    ESP_LOGI(TAG, "Gateway: " IPSTR, IP2STR(&ip_info->gw));
    ESP_LOGI(TAG, "Netmask: " IPSTR, IP2STR(&ip_info->netmask));
    
    eth_connected = true;
    xEventGroupSetBits(network_event_group, ETH_CONNECTED_BIT);
}

void init_w5500_ethernet(void) {
    ESP_LOGI(TAG, "Initializing W5500 Ethernet...");
    
    // Initialize SPI bus
    spi_bus_config_t buscfg = {
        .mosi_io_num = W5500_MOSI_PIN,
        .miso_io_num = W5500_MISO_PIN,
        .sclk_io_num = W5500_SCK_PIN,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &buscfg, SPI_DMA_CH_AUTO));
    
    // W5500 SPI device
    spi_device_interface_config_t devcfg = {
        .command_bits = 16,
        .address_bits = 8,
        .mode = 0,
        .clock_speed_hz = W5500_SPI_CLOCK_MHZ * 1000 * 1000,
        .spics_io_num = W5500_CS_PIN,
        .queue_size = 20,
    };
    ESP_ERROR_CHECK(spi_bus_add_device(SPI2_HOST, &devcfg, &w5500_spi));
    
    // Reset W5500
    gpio_set_direction(W5500_RST_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(W5500_RST_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(W5500_RST_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(10));
    
    // Initialize TCP/IP stack
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);
    
    // W5500 MAC and PHY config
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.reset_gpio_num = -1;
    
    eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(SPI1_HOST, &devcfg);
    w5500_config.int_gpio_num = W5500_INT_PIN;
    
    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500_config, &mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_config);
    
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));
    
    // Attach driver to TCP/IP stack
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    
    // Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, 
                                               &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, 
                                               &got_ip_event_handler, NULL));
    
    // Start Ethernet
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
    
    ESP_LOGI(TAG, "W5500 Ethernet initialized");
}

void init_mqtt(void) {
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
        .credentials.username = MQTT_USERNAME,
        .credentials.authentication.password = MQTT_PASSWORD,
    };
    
    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID, 
                                   mqtt_event_handler, NULL);
    esp_mqtt_client_start(mqtt_client);
    
    ESP_LOGI(TAG, "MQTT client started");
}

// ===================== DISPLAY (SSD1306 OLED) =====================
void init_display(void) {
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = I2C_MASTER_SDA_IO,
        .scl_io_num = I2C_MASTER_SCL_IO,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_MASTER_FREQ_HZ,
    };
    
    i2c_param_config(I2C_MASTER_NUM, &conf);
    i2c_driver_install(I2C_MASTER_NUM, conf.mode, 0, 0, 0);
    
    ESP_LOGI(TAG, "I2C Display initialized");
    // Note: Add SSD1306 driver library for actual display control
}

void update_display(void) {
    // TODO: Implement with SSD1306 library
    // Show: Network status, device count, last packet time, alerts
}

// ===================== BUZZER ALERTS =====================
void buzzer_beep(int count, int duration_ms) {
    for (int i = 0; i < count; i++) {
        gpio_set_level(BUZZER_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(duration_ms));
        gpio_set_level(BUZZER_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void alert_low_battery(uint8_t device_id) {
    buzzer_beep(3, 200);
    char msg[64];
    snprintf(msg, sizeof(msg), "Low battery on device 0x%02X", device_id);
    mqtt_publish_alert("low_battery", device_id, msg);
}

void alert_device_timeout(uint8_t device_id) {
    buzzer_beep(2, 500);
    char msg[64];
    snprintf(msg, sizeof(msg), "Device 0x%02X timeout - no heartbeat", device_id);
    mqtt_publish_alert("timeout", device_id, msg);
}

// ===================== PACKET PROCESSING =====================
void process_received_packet(uint8_t* data, size_t len) {
    packets_received++;
    gpio_set_level(STATUS_LED_PIN, 1);
    
    uint8_t decrypted[len];
    memcpy(decrypted, data, len);
    decrypt_packet(decrypted, len);
    
    if (len == sizeof(lora_packet_t)) {
        lora_packet_t* pkt = (lora_packet_t*)decrypted;
        
        // Whitelist check
        if (!is_whitelisted(pkt->device_id)) {
            ESP_LOGW(TAG, "Rejected: Device 0x%02X not whitelisted", pkt->device_id);
            packets_rejected++;
            gpio_set_level(STATUS_LED_PIN, 0);
            return;
        }
        
        // MAC verification
        uint8_t saved_mac[4];
        memcpy(saved_mac, pkt->mac, 4);
        memset(pkt->mac, 0, 4);
        
        if (!verify_mac((uint8_t*)pkt, sizeof(lora_packet_t), saved_mac)) {
            ESP_LOGW(TAG, "MAC verification failed - dropping");
            packets_rejected++;
            gpio_set_level(STATUS_LED_PIN, 0);
            return;
        }
        
        // Valid packet
        packets_processed++;
        ESP_LOGI(TAG, "Valid packet: ID=0x%02X CNT=%lu BATT=%dmV Status=0x%02X",
                 pkt->device_id, pkt->counter, pkt->battery_mv, pkt->status);
        
        // Update device registry
        update_device_status(pkt->device_id, pkt->counter, pkt->battery_mv, -80);
        
        // Check for low battery
        if (pkt->status & 0x01) {
            alert_low_battery(pkt->device_id);
        }
        
        // Publish to MQTT
        mqtt_publish_data(pkt, -80);
        
    } else if (len == sizeof(heartbeat_packet_t)) {
        heartbeat_packet_t* hb = (heartbeat_packet_t*)decrypted;
        
        if (!is_whitelisted(hb->device_id)) {
            packets_rejected++;
            gpio_set_level(STATUS_LED_PIN, 0);
            return;
        }
        
        uint8_t saved_mac[4];
        memcpy(saved_mac, hb->mac, 4);
        memset(hb->mac, 0, 4);
        
        if (!verify_mac((uint8_t*)hb, sizeof(heartbeat_packet_t), saved_mac)) {
            packets_rejected++;
            gpio_set_level(STATUS_LED_PIN, 0);
            return;
        }
        
        packets_processed++;
        ESP_LOGI(TAG, "Heartbeat: ID=0x%02X RSSI=%d SNR=%d BATT=%dmV",
                 hb->device_id, hb->rssi, hb->snr, hb->battery_mv);
        
        update_device_status(hb->device_id, hb->counter, hb->battery_mv, hb->rssi);
        
        if (hb->status & 0x01) {
            alert_low_battery(hb->device_id);
        }
        
        mqtt_publish_heartbeat(hb);
    } else {
        ESP_LOGW(TAG, "Unknown packet format (%d bytes)", len);
        packets_rejected++;
    }
    
    gpio_set_level(STATUS_LED_PIN, 0);
}

// ===================== TASKS =====================
void uart_rx_task(void* arg) {
    uint8_t* rx_buffer = malloc(E22_UART_BUF_SIZE);
    
    ESP_LOGI(TAG, "UART RX task started");
    
    while (1) {
        int len = uart_read_bytes(E22_UART_NUM, rx_buffer, E22_UART_BUF_SIZE,
                                  pdMS_TO_TICKS(1000));
        
        if (len > 0) {
            process_received_packet(rx_buffer, len);
        }
        
        esp_task_wdt_reset();
    }
    
    free(rx_buffer);
}

void heartbeat_monitor_task(void* arg) {
    ESP_LOGI(TAG, "Heartbeat monitor task started");
    
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(60000));  // Check every minute
        
        int64_t now = esp_timer_get_time() / 1000;
        
        for (int i = 0; i < device_count; i++) {
            if (device_registry[i].is_alive) {
                int64_t elapsed = now - device_registry[i].last_seen;
                
                if (elapsed > HEARTBEAT_TIMEOUT_MS) {
                    ESP_LOGW(TAG, "Device 0x%02X timeout (%lld ms since last seen)",
                             device_registry[i].device_id, elapsed);
                    device_registry[i].is_alive = false;
                    alert_device_timeout(device_registry[i].device_id);
                }
            }
        }
        
        esp_task_wdt_reset();
    }
}

void network_recovery_task(void* arg) {
    ESP_LOGI(TAG, "Network recovery task started");
    
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(NETWORK_RECOVERY_INTERVAL_MS));
        
        // Check Ethernet
        if (!eth_connected) {
            ESP_LOGW(TAG, "Ethernet disconnected - attempting recovery...");
            
            // Reset W5500
            gpio_set_level(W5500_RST_PIN, 0);
            vTaskDelay(pdMS_TO_TICKS(100));
            gpio_set_level(W5500_RST_PIN, 1);
            vTaskDelay(pdMS_TO_TICKS(500));
            
            // Restart Ethernet
            esp_eth_stop(eth_handle);
            vTaskDelay(pdMS_TO_TICKS(1000));
            esp_eth_start(eth_handle);
        }
        
        // Check MQTT
        if (eth_connected && !mqtt_connected) {
            ESP_LOGW(TAG, "MQTT disconnected - reconnecting...");
            esp_mqtt_client_reconnect(mqtt_client);
        }
        
        esp_task_wdt_reset();
    }
}

void status_task(void* arg) {
    ESP_LOGI(TAG, "Status task started");
    
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(DISPLAY_UPDATE_MS));
        
        // Update display
        update_display();
        
        // LED heartbeat (slow blink)
        static int counter = 0;
        if (counter++ % 2 == 0) {
            gpio_set_level(STATUS_LED_PIN, 1);
            vTaskDelay(pdMS_TO_TICKS(50));
            gpio_set_level(STATUS_LED_PIN, 0);
        }
        
        esp_task_wdt_reset();
    }
}

void stats_task(void* arg) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(60000));  // Every minute
        
        ESP_LOGI(TAG, "=== STATS ===");
        ESP_LOGI(TAG, "Received: %lu | Processed: %lu | Rejected: %lu",
                 packets_received, packets_processed, packets_rejected);
        ESP_LOGI(TAG, "Ethernet: %s | MQTT: %s",
                 eth_connected ? "UP" : "DOWN",
                 mqtt_connected ? "UP" : "DOWN");
        ESP_LOGI(TAG, "Active devices: %d", device_count);
        
        for (int i = 0; i < device_count; i++) {
            ESP_LOGI(TAG, "  Device 0x%02X: %s (BATT=%dmV RSSI=%d)",
                     device_registry[i].device_id,
                     device_registry[i].is_alive ? "ALIVE" : "TIMEOUT",
                     device_registry[i].last_battery_mv,
                     device_registry[i].last_rssi);
        }
        
        esp_task_wdt_reset();
    }
}

// ===================== INITIALIZATION =====================
void gpio_init(void) {
    // E22 control pins
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << E22_M0_PIN) | (1ULL << E22_M1_PIN),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
    };
    gpio_config(&io_conf);
    
    // E22 AUX pin
    io_conf.pin_bit_mask = (1ULL << E22_AUX_PIN);
    io_conf.mode = GPIO_MODE_INPUT;
    gpio_config(&io_conf);
    
    // Output pins
    io_conf.pin_bit_mask = (1ULL << STATUS_LED_PIN) | (1ULL << BUZZER_PIN);
    io_conf.mode = GPIO_MODE_OUTPUT;
    gpio_config(&io_conf);
    
    // W5500 reset
    gpio_set_direction(W5500_RST_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(W5500_RST_PIN, 1);
    
    gpio_set_level(E22_M0_PIN, 0);
    gpio_set_level(E22_M1_PIN, 0);
    gpio_set_level(STATUS_LED_PIN, 0);
    gpio_set_level(BUZZER_PIN, 0);
}

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
    
    ESP_LOGI(TAG, "UART initialized");
}

// ===================== MAIN =====================
void app_main(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "   Nova NC1020 - Main Controller");
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
    
    // Create event group
    network_event_group = xEventGroupCreate();
    
    // Initialize peripherals
    gpio_init();
    uart_init();
    init_display();
    
    // Boot sequence (LED + buzzer)
    for (int i = 0; i < 3; i++) {
        gpio_set_level(STATUS_LED_PIN, 1);
        buzzer_beep(1, 100);
        gpio_set_level(STATUS_LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // Configure E22
    e22_configure();
    
    // Initialize Ethernet
    init_w5500_ethernet();
    
    // Wait for Ethernet connection
    ESP_LOGI(TAG, "Waiting for Ethernet...");
    xEventGroupWaitBits(network_event_group, ETH_CONNECTED_BIT,
                       pdFALSE, pdTRUE, pdMS_TO_TICKS(10000));
    
    if (eth_connected) {
        ESP_LOGI(TAG, "Ethernet connected, starting MQTT...");
        init_mqtt();
    } else {
        ESP_LOGW(TAG, "Ethernet timeout, will retry in background");
    }
    
    // Initialize device registry
    memset(device_registry, 0, sizeof(device_registry));
    
    // Configure watchdog
    ESP_LOGI(TAG, "Configuring watchdog timer (%ds)...", WATCHDOG_TIMEOUT_S);
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = WATCHDOG_TIMEOUT_S * 1000,
        .idle_core_mask = (1 << portNUM_PROCESSORS) - 1,
        .trigger_panic = true
    };
    ESP_ERROR_CHECK(esp_task_wdt_init(&wdt_config));
    
    // Create tasks and add to watchdog
    TaskHandle_t uart_task, hb_task, net_task, status_task_handle, stats_task_handle;
    
    xTaskCreate(uart_rx_task, "uart_rx", 4096, NULL, 10, &uart_task);
    xTaskCreate(heartbeat_monitor_task, "hb_monitor", 3072, NULL, 5, &hb_task);
    xTaskCreate(network_recovery_task, "net_recovery", 3072, NULL, 5, &net_task);
    xTaskCreate(status_task, "status", 2048, NULL, 3, &status_task_handle);
    xTaskCreate(stats_task, "stats", 2048, NULL, 2, &stats_task_handle);
    
    esp_task_wdt_add(uart_task);
    esp_task_wdt_add(hb_task);
    esp_task_wdt_add(net_task);
    esp_task_wdt_add(status_task_handle);
    esp_task_wdt_add(stats_task_handle);
    
    ESP_LOGI(TAG, "NC1020 ready - monitoring network...");
    buzzer_beep(2, 200);  // Ready signal
}

