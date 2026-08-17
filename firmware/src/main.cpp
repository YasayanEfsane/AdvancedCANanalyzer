#include <Arduino.h>
#include <SPI.h>
#include <driver/gpio.h>
#include <esp_timer.h>

#include "config.hpp"
#include "mcp2515.hpp"

namespace {

SPIClass canSpi(VSPI);
Mcp2515 canController(canSpi, config::kMcpCsPin, config::kSpiClockHz);

QueueHandle_t frameQueue = nullptr;
TaskHandle_t receiveTaskHandle = nullptr;

volatile uint32_t receivedFrames = 0;
volatile uint32_t queueDrops = 0;
volatile uint32_t hardwareOverflows = 0;
volatile uint32_t malformedFrames = 0;
volatile bool controllerReady = false;

void IRAM_ATTR onCanInterrupt() {
  // The MCP2515 INT output is level-active-low. Never call SPI, Serial, malloc,
  // logging, or any non-IRAM-safe function here. A direct task notification is
  // an allocation-free wake-up primitive and keeps ISR latency deterministic.
  BaseType_t higherPriorityTaskWoken = pdFALSE;
  if (receiveTaskHandle != nullptr) {
    vTaskNotifyGiveFromISR(receiveTaskHandle, &higherPriorityTaskWoken);
  }
  if (higherPriorityTaskWoken == pdTRUE) {
    portYIELD_FROM_ISR();
  }
}

void initTimerCallback(void* argument) {
  // ESP_TIMER_TASK dispatch means this callback is not a hardware ISR. It only
  // releases the initialization task; it still performs no SPI or serial I/O.
  xTaskNotifyGive(static_cast<TaskHandle_t>(argument));
}

bool waitForOneShotTimer(esp_timer_handle_t timer, const uint64_t microseconds) {
  // This is an event wait, not a busy wait: the scheduler can run the serial
  // and system tasks while the MCP2515 oscillator/mode change settles.
  if (esp_timer_start_once(timer, microseconds) != ESP_OK) {
    return false;
  }
  return ulTaskNotifyTake(pdTRUE, portMAX_DELAY) > 0;
}

void enqueueFrame(const uint8_t receiveBuffer) {
  CanFrame frame{};
  if (!canController.readFrame(receiveBuffer, frame)) {
    ++malformedFrames;
    return;
  }
  frame.timestampUs = static_cast<uint64_t>(esp_timer_get_time());

  ++receivedFrames;
  if (xQueueSendToBack(frameQueue, &frame, 0) != pdTRUE) {
    // Never wait here. Preserving the high-priority MCP2515 drain path is more
    // important than stalling it behind a saturated UART queue.
    ++queueDrops;
  }
}

void receiveTask(void*) {
  for (;;) {
    // Zero CPU is consumed until the falling edge on MCP2515 INT wakes us.
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

    for (;;) {
      const uint8_t flags = canController.interruptFlags();
      const uint8_t actionable =
          flags & (Mcp2515::kRx0Interrupt | Mcp2515::kRx1Interrupt |
                   Mcp2515::kErrorInterrupt |
                   Mcp2515::kMessageErrorInterrupt);
      if (actionable == 0) {
        break;
      }

      if ((flags & Mcp2515::kRx0Interrupt) != 0) {
        enqueueFrame(0);
      }
      if ((flags & Mcp2515::kRx1Interrupt) != 0) {
        enqueueFrame(1);
      }
      if ((flags & Mcp2515::kErrorInterrupt) != 0) {
        const uint8_t errors = canController.errorFlags();
        if ((errors & 0xC0U) != 0) {
          ++hardwareOverflows;
          canController.clearReceiveOverflowFlags();
        }
        canController.clearInterruptFlags(Mcp2515::kErrorInterrupt);
      }
      if ((flags & Mcp2515::kMessageErrorInterrupt) != 0) {
        canController.clearInterruptFlags(Mcp2515::kMessageErrorInterrupt);
      }
    }
  }
}

size_t formatFrame(const CanFrame& frame, char* output,
                   const size_t outputSize) {
  const char type = frame.remote ? (frame.extended ? 'X' : 'R')
                                 : (frame.extended ? 'E' : 'S');
  int used = 0;
  if (frame.extended) {
    used = snprintf(output, outputSize, "%c%08lX:%u:", type,
                    static_cast<unsigned long>(frame.id), frame.dlc);
  } else {
    used = snprintf(output, outputSize, "%c%03lX:%u:", type,
                    static_cast<unsigned long>(frame.id), frame.dlc);
  }
  if (used < 0 || static_cast<size_t>(used) >= outputSize) {
    return 0;
  }

  size_t cursor = static_cast<size_t>(used);
  for (size_t index = 0; index < 8; ++index) {
    const int written = snprintf(output + cursor, outputSize - cursor,
                                 index == 7 ? "%02X\n" : "%02X,",
                                 frame.data[index]);
    if (written < 0 || static_cast<size_t>(written) >= outputSize - cursor) {
      return 0;
    }
    cursor += static_cast<size_t>(written);
  }
  return cursor;
}

void serialTask(void*) {
  char line[64]{};
  uint32_t lastStatsMs = millis();

  Serial.printf("#BOOT:AdvancedCANAnalyzer:v1\n");
  Serial.printf("#CFG:bitrate=%lu,oscillator=%lu,serial=%lu,mode=listen-only\n",
                static_cast<unsigned long>(config::kCanBitrate),
                static_cast<unsigned long>(config::kMcpOscillatorHz),
                static_cast<unsigned long>(config::kSerialBaud));

  for (;;) {
    CanFrame frame{};
    if (xQueueReceive(frameQueue, &frame, pdMS_TO_TICKS(100)) == pdTRUE) {
      const size_t length = formatFrame(frame, line, sizeof(line));
      if (length > 0) {
        // A single write avoids interleaving partial fields and lets the ESP32
        // UART driver move bytes in the background from its enlarged TX ring.
        Serial.write(reinterpret_cast<const uint8_t*>(line), length);
      }
    }

    const uint32_t nowMs = millis();
    if (nowMs - lastStatsMs >= 1000U) {
      lastStatsMs = nowMs;
      Serial.printf("#STAT:ready=%u,rx=%lu,queue_drop=%lu,hw_overflow=%lu,bad=%lu\n",
                    controllerReady ? 1U : 0U,
                    static_cast<unsigned long>(receivedFrames),
                    static_cast<unsigned long>(queueDrops),
                    static_cast<unsigned long>(hardwareOverflows),
                    static_cast<unsigned long>(malformedFrames));
    }
  }
}

void initializationTask(void*) {
  esp_timer_handle_t initTimer = nullptr;
  esp_timer_create_args_t timerArgs{};
  timerArgs.callback = &initTimerCallback;
  timerArgs.arg = xTaskGetCurrentTaskHandle();
  timerArgs.dispatch_method = ESP_TIMER_TASK;
  timerArgs.name = "mcp-init";

  if (esp_timer_create(&timerArgs, &initTimer) != ESP_OK) {
    Serial.println("#FATAL:esp_timer_create_failed");
    vTaskDelete(nullptr);
    return;
  }

  canController.begin(config::kSpiSckPin, config::kSpiMisoPin,
                      config::kSpiMosiPin);
  canController.reset();

  if (!waitForOneShotTimer(initTimer, config::kResetRecoveryUs) ||
      !canController.configureListenOnly(config::kCanBitrate,
                                         config::kMcpOscillatorHz) ||
      !waitForOneShotTimer(initTimer, config::kModeSettleUs) ||
      !canController.isListenOnly()) {
    Serial.println("#FATAL:mcp2515_initialization_failed");
    esp_timer_delete(initTimer);
    vTaskDelete(nullptr);
    return;
  }

  if (xTaskCreatePinnedToCore(receiveTask, "can-rx",
                              config::kRxTaskStackWords, nullptr,
                              config::kRxTaskPriority, &receiveTaskHandle,
                              config::kRxTaskCore) != pdPASS) {
    Serial.println("#FATAL:receive_task_creation_failed");
    esp_timer_delete(initTimer);
    vTaskDelete(nullptr);
    return;
  }

  pinMode(config::kMcpIntPin, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(config::kMcpIntPin), onCanInterrupt,
                  FALLING);
  controllerReady = true;

  // Cover the case where a frame arrived after CANINTE was enabled but before
  // attachInterrupt completed: INT is level-low and may already be asserted.
  if (digitalRead(config::kMcpIntPin) == LOW) {
    xTaskNotifyGive(receiveTaskHandle);
  }

  esp_timer_delete(initTimer);
  vTaskDelete(nullptr);
}

}  // namespace

void setup() {
  Serial.setTxBufferSize(config::kSerialTxBufferBytes);
  Serial.begin(config::kSerialBaud);

  frameQueue = xQueueCreate(config::kFrameQueueDepth, sizeof(CanFrame));
  if (frameQueue == nullptr) {
    Serial.println("#FATAL:frame_queue_allocation_failed");
    return;
  }

  if (xTaskCreatePinnedToCore(serialTask, "serial-tx",
                              config::kSerialTaskStackWords, nullptr,
                              config::kSerialTaskPriority, nullptr,
                              config::kSerialTaskCore) != pdPASS) {
    Serial.println("#FATAL:serial_task_creation_failed");
    return;
  }
  if (xTaskCreatePinnedToCore(initializationTask, "mcp-init", 4096, nullptr, 4,
                              nullptr, config::kRxTaskCore) != pdPASS) {
    Serial.println("#FATAL:initialization_task_creation_failed");
  }
}

void loop() {
  // Runtime work belongs to event-driven FreeRTOS tasks. Delete Arduino's loop
  // task instead of polling a flag or inserting delay().
  vTaskDelete(nullptr);
}
