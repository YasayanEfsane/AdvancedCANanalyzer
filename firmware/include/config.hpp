#pragma once

#include <Arduino.h>

// Compile-time settings may be overridden from platformio.ini without touching
// source code. Only timing combinations validated in mcp2515.cpp are accepted.
#ifndef CAN_BITRATE_KBPS
#define CAN_BITRATE_KBPS 500
#endif

#ifndef MCP2515_OSCILLATOR_MHZ
#define MCP2515_OSCILLATOR_MHZ 8
#endif

#ifndef SERIAL_BAUD
#define SERIAL_BAUD 921600
#endif

static_assert(CAN_BITRATE_KBPS == 250 || CAN_BITRATE_KBPS == 500,
              "CAN_BITRATE_KBPS must be 250 or 500");
static_assert(MCP2515_OSCILLATOR_MHZ == 8 || MCP2515_OSCILLATOR_MHZ == 16,
              "MCP2515_OSCILLATOR_MHZ must be 8 or 16");

namespace config {

// ESP32 VSPI pins. GPIO 27 and 26 avoid the classic ESP32 boot-strapping pins.
constexpr uint8_t kSpiSckPin = 18;
constexpr uint8_t kSpiMisoPin = 19;
constexpr uint8_t kSpiMosiPin = 23;
constexpr uint8_t kMcpCsPin = 27;
constexpr uint8_t kMcpIntPin = 26;

constexpr uint32_t kSpiClockHz = 8'000'000;
constexpr uint32_t kCanBitrate = CAN_BITRATE_KBPS * 1'000UL;
constexpr uint32_t kMcpOscillatorHz = MCP2515_OSCILLATOR_MHZ * 1'000'000UL;
constexpr uint32_t kSerialBaud = SERIAL_BAUD;

// The queue absorbs short CAN bursts while the UART task drains its TX buffer.
// It does not make an overloaded ASCII/UART link lossless indefinitely.
constexpr size_t kFrameQueueDepth = 512;
constexpr size_t kSerialTxBufferBytes = 8192;

constexpr uint64_t kResetRecoveryUs = 10'000;
constexpr uint64_t kModeSettleUs = 2'000;

constexpr uint32_t kRxTaskStackWords = 4096;
constexpr uint32_t kSerialTaskStackWords = 4096;
constexpr UBaseType_t kRxTaskPriority = 5;
constexpr UBaseType_t kSerialTaskPriority = 2;
constexpr BaseType_t kRxTaskCore = 1;
constexpr BaseType_t kSerialTaskCore = 0;

}  // namespace config

