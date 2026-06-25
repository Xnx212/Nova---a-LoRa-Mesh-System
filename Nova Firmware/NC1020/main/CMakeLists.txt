idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES driver nvs_flash esp_driver_uart esp_driver_gpio esp_driver_spi esp_driver_i2c esp_timer mbedtls esp_netif esp_eth)
