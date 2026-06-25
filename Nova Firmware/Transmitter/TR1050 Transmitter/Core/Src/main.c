/* USER CODE BEGIN Header */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "aes.h"
#include <string.h>
#include <stdio.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef enum {
    E22_MODE_NORMAL = 0,      // M1=0, M0=0 - Transparent transmission
    E22_MODE_WOR = 1,         // M1=0, M0=1 - Wake on radio
    E22_MODE_POWERSAVE = 3,   // M1=1, M0=1 - Sleep mode
    E22_MODE_CONFIG = 2       // M1=1, M0=0 - Configuration mode
} E22_Mode_t;

// E22 Configuration Structure (Per datasheet section 7.2)
typedef struct __attribute__((packed)) {
    uint8_t addh;           // 0x00: Address high byte
    uint8_t addl;           // 0x01: Address low byte
    uint8_t netid;          // 0x02: Network ID
    uint8_t reg0;           // 0x03: UART baud + parity + air data rate
    uint8_t reg1;           // 0x04: Sub-packet + RSSI ambient noise + TX power
    uint8_t reg2;           // 0x05: Channel (0-80)
    uint8_t reg3;           // 0x06: RSSI enable + fixed point + repeater + LBT + WOR
    uint8_t crypt_h;        // 0x07: Encryption key high (write only)
    uint8_t crypt_l;        // 0x08: Encryption key low (write only)
} E22_Config_t;

// LoRa Packet Structure (must match repeater and controller)
typedef struct __attribute__((packed)) {
    uint8_t device_id;
    uint8_t nc_number;
    uint32_t counter;
    uint16_t battery_mv;
    uint8_t status;
    uint32_t timestamp;
    uint8_t mac[4];
    uint8_t padding[15];
} LoRaPacket;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
// Configuration
#define DEVICE_ID 0x01              // Unique device ID
#define NC_NUMBER 0x01              // Network controller number
#define BATTERY_LOW_THRESHOLD 10.5  // Volts
#define UART_TIMEOUT 1000           // ms

// E22 Commands
#define E22_CMD_READ_CONFIG     0xC1
#define E22_CMD_WRITE_CONFIG    0xC0
#define E22_CMD_READ_VERSION    0xC3

// AES-128 Key (MUST match all nodes - CHANGE THIS!)
const uint8_t AES_KEY[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x97, 0x46, 0x09, 0xCF, 0x4F, 0x3C
};
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
ADC_HandleTypeDef hadc;

UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_ADC_Init(void);
/* USER CODE BEGIN PFP */
static uint32_t packet_counter = 0;
static struct AES_ctx aes_ctx;
// E22 Module Functions
void E22_Set_Mode(E22_Mode_t mode);
void E22_Wait_AUX_High(void);
void E22_Configure(void);

// Application Functions
float Read_Battery_Voltage(void);
void Send_LoRa_Packet(void);
void Enter_Stop_Mode(void);
void TR_Init(void);
void TR_Main_Cycle(void);

// Encryption Functions
void Compute_MAC(uint8_t* data, uint16_t len, uint8_t* mac_out);
void Encrypt_Packet(LoRaPacket* pkt);

// Debug Functions
//void Debug_Print(const char* msg);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
void E22_Set_Mode(E22_Mode_t mode) {
    switch(mode) {
        case E22_MODE_NORMAL:
            HAL_GPIO_WritePin(GPIOB, M0_Pin, GPIO_PIN_RESET);
            HAL_GPIO_WritePin(GPIOB, M1_Pin, GPIO_PIN_RESET);
            //Debug_Print("[E22] Mode: NORMAL\r\n");
            break;
        case E22_MODE_WOR:
            HAL_GPIO_WritePin(GPIOB, M0_Pin, GPIO_PIN_SET);
            HAL_GPIO_WritePin(GPIOB, M1_Pin, GPIO_PIN_RESET);
            //Debug_Print("[E22] Mode: WOR\r\n");
            break;
        case E22_MODE_POWERSAVE:
            HAL_GPIO_WritePin(GPIOB, M0_Pin, GPIO_PIN_SET);
            HAL_GPIO_WritePin(GPIOB, M1_Pin, GPIO_PIN_SET);
            //Debug_Print("[E22] Mode: POWER SAVE\r\n");
            break;
        case E22_MODE_CONFIG:
            HAL_GPIO_WritePin(GPIOB, M0_Pin, GPIO_PIN_RESET);
            HAL_GPIO_WritePin(GPIOB, M1_Pin, GPIO_PIN_SET);
            //Debug_Print("[E22] Mode: CONFIG\r\n");
            break;
    }
    HAL_Delay(50); // Wait for mode change
}

void E22_Wait_AUX_High(void) {
    uint32_t timeout = HAL_GetTick() + 2000;
    while (HAL_GPIO_ReadPin(GPIOB, NAux_Pin) == GPIO_PIN_RESET) {
            if (HAL_GetTick() > timeout) {
                //Debug_Print("[E22] AUX timeout!\r\n");
                break;
            }
            HAL_Delay(1);
    }
}

// ===================== E22 CONFIGURATION =====================
void E22_Configure(void) {
    E22_Config_t config;
    uint8_t cmd_buf[12];

    //Debug_Print("[E22] Configuring module...\r\n");

    // Enter config mode
    E22_Set_Mode(E22_MODE_CONFIG);
    E22_Wait_AUX_High();
    HAL_Delay(50);

    // Read current configuration (datasheet section 7.1)
    cmd_buf[0] = E22_CMD_READ_CONFIG;  // 0xC1
    cmd_buf[1] = 0x00;                  // Start address
    cmd_buf[2] = 0x09;                  // Length (9 bytes: 0x00-0x08)

    HAL_UART_Transmit(&huart2, cmd_buf, 3, UART_TIMEOUT);
    HAL_Delay(100);

    uint8_t rx_buf[12];
    HAL_StatusTypeDef status = HAL_UART_Receive(&huart2, rx_buf, 12, UART_TIMEOUT);

    if (status == HAL_OK && rx_buf[0] == 0xC1) {
        // Parse response (format: C1 + start_addr + length + data)
        memcpy(&config, &rx_buf[3], 9);
        //Debug_Print("[E22] Config read OK\r\n");
    } else {
        // Use defaults if read fails
        memset(&config, 0, sizeof(config));
        //Debug_Print("[E22] Using defaults\r\n");
    }

    // Configure registers per datasheet
    config.addh = 0x00;           // Module address high (broadcast)
    config.addl = 0x00;           // Module address low (broadcast)
    config.netid = NC_NUMBER;     // Network ID (must match NC and XR)

    // REG0 (0x03): UART + Air data rate
    // Bits 7-5: UART baud (011 = 9600)
    // Bits 4-3: Parity (00 = 8N1)
    // Bits 2-0: Air rate (010 = 2.4kbps)
    config.reg0 = 0x62;           // 0b01100010 = 9600bps, 8N1, 2.4kbps

    // REG1 (0x04): Sub-packet + RSSI + Power
    // Bits 7-6: Sub-packet (00 = 240 bytes)
    // Bit 5: RSSI ambient noise (0 = disabled)
    // Bits 4-2: Reserved (000)
    // Bits 1-0: TX power (00 = 22dBm)
    config.reg1 = 0x00;           // 0b00000000 = 240 bytes, no ambient RSSI, 22dBm

    // REG2 (0x05): Channel
    // Channel = 0x11 (17) → Frequency = 850.125 + 17*1 = 867.125 MHz
    // For 915 MHz: use channel 0x41 (65) → 915.125 MHz
    config.reg2 = 0x41;           // Channel 65 = 915.125 MHz (adjust for region)

    // REG3 (0x06): RSSI + Fixed point + Repeater + LBT + WOR
    // Bit 7: RSSI enable (0 = disabled)
    // Bit 6: Fixed point (0 = transparent mode)
    // Bit 5: Repeater (0 = disabled)
    // Bit 4: LBT (0 = disabled)
    // Bit 3: WOR mode (0 = WOR receiver)
    // Bits 2-0: WOR cycle (000 = 500ms)
    config.reg3 = 0x00;           // 0b00000000 = All disabled, transparent mode

    // Encryption keys (write only, read returns 0)
    config.crypt_h = 0x00;        // No hardware encryption (we use AES)
    config.crypt_l = 0x00;

    // Write configuration (datasheet section 7.1)
    cmd_buf[0] = E22_CMD_WRITE_CONFIG;  // 0xC0
    cmd_buf[1] = 0x00;                   // Start address
    cmd_buf[2] = 0x09;                   // Length
    memcpy(&cmd_buf[3], &config, 9);

    HAL_UART_Transmit(&huart2, cmd_buf, 12, UART_TIMEOUT);
    E22_Wait_AUX_High();
    HAL_Delay(100);

    // Verify configuration by reading back
    cmd_buf[0] = E22_CMD_READ_CONFIG;
    cmd_buf[1] = 0x00;
    cmd_buf[2] = 0x09;
    HAL_UART_Transmit(&huart2, cmd_buf, 3, UART_TIMEOUT);
    HAL_Delay(50);

    if (HAL_UART_Receive(&huart2, rx_buf, 12, UART_TIMEOUT) == HAL_OK) {
        if (rx_buf[0] == 0xC1 && rx_buf[5] == config.reg0) {
        	HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_SET);
        	HAL_Delay(50);
        	HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_RESET);
        } else {
            for (int i = 0; i <= 2; i++)
            {
            	HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_SET);
            	HAL_Delay(50);
            	HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_RESET);
            }
        }
    }

    //Debug_Print("[E22] Configuration complete\r\n");

    // Return to normal mode
    E22_Set_Mode(E22_MODE_NORMAL);
    HAL_Delay(50);
}

// ===================== BATTERY MEASUREMENT =====================
float Read_Battery_Voltage(void) {
    uint32_t adc_value = 0;

    // Start ADC conversion
    HAL_ADC_Start(&hadc);
    if (HAL_ADC_PollForConversion(&hadc, 100) == HAL_OK) {
        adc_value = HAL_ADC_GetValue(&hadc);
    }
    HAL_ADC_Stop(&hadc);

    // Voltage divider calculation: 51K + 51K (divide by 2)
    // Vbatt = (ADC / 4096) * 3.3V * 2
    float voltage = (adc_value / 4096.0f) * 3.3f * 2.0f;

    return voltage;
}

// ===================== ENCRYPTION & MAC =====================
void Compute_MAC(uint8_t* data, uint16_t len, uint8_t* mac_out) {
    uint8_t temp[16] = {0};

    // Copy last 16 bytes (or less if packet smaller)
    uint16_t copy_len = (len >= 16) ? 16 : len;
    memcpy(temp, data + len - copy_len, copy_len);

    // Encrypt to generate MAC
    AES_init_ctx(&aes_ctx, AES_KEY);
    AES_ECB_encrypt(&aes_ctx, temp);

    // Use first 4 bytes as MAC
    memcpy(mac_out, temp, 4);
}

void Encrypt_Packet(LoRaPacket* pkt) {
    // Encrypt entire packet (16 bytes exactly)
    AES_init_ctx(&aes_ctx, AES_KEY);
    for (int i = 0; i < 32; i += 16) {
        AES_ECB_encrypt(&aes_ctx, ((uint8_t*)pkt) + i);
    }

}

// ===================== LORA TRANSMIT =====================
void Send_LoRa_Packet(void) {
    LoRaPacket packet = {0};
    char debug_msg[64];

    //Debug_Print("\r\n[TX] Building packet...\r\n");

    // LED ON
    HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_SET);

    // Read battery voltage
    float battery = Read_Battery_Voltage();


    // Build packet
    packet.device_id = DEVICE_ID;
    packet.nc_number = NC_NUMBER;
    packet.counter = packet_counter++;
    packet.battery_mv = (uint16_t)(battery * 1000);
    packet.status = (battery < BATTERY_LOW_THRESHOLD) ? 0x01 : 0x00;
    packet.timestamp = HAL_GetTick();



    // Compute MAC (before encryption)
    Compute_MAC((uint8_t*)&packet, sizeof(packet) - 4, packet.mac);

    // Encrypt packet
    Encrypt_Packet(&packet);

    //Debug_Print("[TX] Packet encrypted\r\n");

    // Ensure module is ready
    E22_Wait_AUX_High();

    // Send via UART (transparent mode)
    HAL_StatusTypeDef status = HAL_UART_Transmit(&huart2, (uint8_t*)&packet,
                                                  sizeof(packet), UART_TIMEOUT);

    if (status == HAL_OK) {
        //Debug_Print("[TX] Packet sent successfully\r\n");
    	HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_RESET);
    	HAL_Delay(50);
    	HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_SET);
    } else {
        //Debug_Print("[TX] ERROR: Transmission failed\r\n");
    	 for (int i = 0; i <= 2; i++)
    	  {
    	     HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_SET);
    	     HAL_Delay(50);
    	     HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_RESET);
    	  }
    }

    // Wait for transmission to complete
    E22_Wait_AUX_High();
    HAL_Delay(100);

    // LED OFF
    HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_RESET);
}

// ===================== POWER MANAGEMENT =====================
void Enter_Stop_Mode(void) {
    //Debug_Print("[PWR] Entering sleep mode...\r\n\r\n");
    HAL_Delay(50); // Allow UART to finish

    // Put E22 in power save mode
    E22_Set_Mode(E22_MODE_POWERSAVE);

    // Enter STOP mode (will wake on EXTI interrupt)
    HAL_SuspendTick();
    HAL_PWR_EnterSTOPMode(PWR_LOWPOWERREGULATOR_ON, PWR_STOPENTRY_WFI);

    // Woken up - reconfigure clocks
    HAL_ResumeTick();
    SystemClock_Config();

    // Wake E22 back to normal mode
    E22_Set_Mode(E22_MODE_NORMAL);
    HAL_Delay(50);

    //Debug_Print("[PWR] Woken up!\r\n");
}

// ===================== INITIALIZATION =====================
void TR_Init(void) {
    char msg[64];

    //Debug_Print("\r\n=================================\r\n");
    //Debug_Print("  Nova TR - Secure Transmitter\r\n");
    //Debug_Print("=================================\r\n");

    sprintf(msg, "Device ID: 0x%02X\r\n", DEVICE_ID);
    //Debug_Print(msg);

    sprintf(msg, "NC Number: 0x%02X\r\n", NC_NUMBER);
    //Debug_Print(msg);

    // Initialize GPIO for mode control
    HAL_GPIO_WritePin(GPIOB, M0_Pin, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(GPIOB, M1_Pin, GPIO_PIN_RESET);
    HAL_Delay(100);

    // Configure E22 module
    E22_Configure();

    // Test battery reading
    float battery = Read_Battery_Voltage();

    if (battery < BATTERY_LOW_THRESHOLD) {
        //Debug_Print("WARNING: Battery LOW!\r\n");
    }

    // Initial LED blink pattern
    for (int i = 0; i < 5; i++) {
        HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_SET);
        HAL_Delay(100);
        HAL_GPIO_WritePin(GPIOA, LED_Pin, GPIO_PIN_RESET);
        HAL_Delay(100);
    }

    //Debug_Print("[TR] Initialization complete\r\n");
    //Debug_Print("Press button to send packet...\r\n\r\n");
}

// ===================== MAIN CYCLE =====================
void TR_Main_Cycle(void) {
    // Send packet
    Send_LoRa_Packet();

    // Enter sleep mode (wake on button press)
    Enter_Stop_Mode();
}
/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */
  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */
  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  MX_ADC_Init();
  /* USER CODE BEGIN 2 */
  TR_Init();
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
   {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */

     // Check if button pressed (PC13 - blue button)
     if (HAL_GPIO_ReadPin(GPIOA, Button_Pin) == GPIO_PIN_RESET) {
         HAL_Delay(50); // Debounce
         if (HAL_GPIO_ReadPin(GPIOA, Button_Pin) == GPIO_PIN_RESET) {
             // Button confirmed pressed
             //Debug_Print("[BTN] Button pressed\r\n");
             TR_Main_Cycle();

             // Wait for release
             while (HAL_GPIO_ReadPin(GPIOA, Button_Pin) == GPIO_PIN_RESET) {
                 HAL_Delay(10);
             }
             HAL_Delay(50); // Debounce release
         }
     }

     HAL_Delay(10); // Small delay to prevent tight loop
   }
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSICalibrationValue = 0;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_5;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_MSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
  PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_USART2;
  PeriphClkInit.Usart2ClockSelection = RCC_USART2CLKSOURCE_PCLK1;
  if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief ADC Initialization Function
  * @param None
  * @retval None
  */
static void MX_ADC_Init(void)
{

  /* USER CODE BEGIN ADC_Init 0 */

  /* USER CODE END ADC_Init 0 */

  ADC_ChannelConfTypeDef sConfig = {0};

  /* USER CODE BEGIN ADC_Init 1 */

  /* USER CODE END ADC_Init 1 */

  /** Configure the global features of the ADC (Clock, Resolution, Data Alignment and number of conversion)
  */
  hadc.Instance = ADC1;
  hadc.Init.OversamplingMode = DISABLE;
  hadc.Init.ClockPrescaler = ADC_CLOCK_SYNC_PCLK_DIV1;
  hadc.Init.Resolution = ADC_RESOLUTION_12B;
  hadc.Init.SamplingTime = ADC_SAMPLETIME_1CYCLE_5;
  hadc.Init.ScanConvMode = ADC_SCAN_DIRECTION_FORWARD;
  hadc.Init.DataAlign = ADC_DATAALIGN_RIGHT;
  hadc.Init.ContinuousConvMode = DISABLE;
  hadc.Init.DiscontinuousConvMode = DISABLE;
  hadc.Init.ExternalTrigConvEdge = ADC_EXTERNALTRIGCONVEDGE_NONE;
  hadc.Init.ExternalTrigConv = ADC_SOFTWARE_START;
  hadc.Init.DMAContinuousRequests = DISABLE;
  hadc.Init.EOCSelection = ADC_EOC_SINGLE_CONV;
  hadc.Init.Overrun = ADC_OVR_DATA_PRESERVED;
  hadc.Init.LowPowerAutoWait = DISABLE;
  hadc.Init.LowPowerFrequencyMode = ENABLE;
  hadc.Init.LowPowerAutoPowerOff = DISABLE;
  if (HAL_ADC_Init(&hadc) != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure for the selected ADC regular channel to be converted.
  */
  sConfig.Channel = ADC_CHANNEL_1;
  sConfig.Rank = ADC_RANK_CHANNEL_NUMBER;
  if (HAL_ADC_ConfigChannel(&hadc, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN ADC_Init 2 */

  /* USER CODE END ADC_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */
  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */
  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */
  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
/* USER CODE BEGIN MX_GPIO_Init_1 */
/* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, LED_Pin|GPIO_PIN_12, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOB, M1_Pin|M0_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : Button_Pin */
  GPIO_InitStruct.Pin = Button_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(Button_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : LED_Pin PA12 */
  GPIO_InitStruct.Pin = LED_Pin|GPIO_PIN_12;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pins : M1_Pin M0_Pin */
  GPIO_InitStruct.Pin = M1_Pin|M0_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pin : NAux_Pin */
  GPIO_InitStruct.Pin = NAux_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(NAux_GPIO_Port, &GPIO_InitStruct);

/* USER CODE BEGIN MX_GPIO_Init_2 */
/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
