#pragma once

#include <Arduino.h>
#include <SPI.h>

struct CanFrame {
  uint64_t timestampUs = 0;
  uint32_t id = 0;
  uint8_t dlc = 0;
  uint8_t data[8]{};
  bool extended = false;
  bool remote = false;
};

// Minimal receive-only MCP2515 driver.
//
// Deliberately omitted: every transmit opcode and normal-mode API. This makes
// accidental CAN injection impossible through this firmware build. The class
// only implements the SPI operations needed to configure Listen-Only mode and
// drain RXB0/RXB1 after the hardware INT pin fires.
class Mcp2515 final {
 public:
  enum InterruptFlag : uint8_t {
    kRx0Interrupt = 0x01,
    kRx1Interrupt = 0x02,
    kErrorInterrupt = 0x20,
    kMessageErrorInterrupt = 0x80,
  };

  explicit Mcp2515(SPIClass& spi, uint8_t chipSelectPin,
                   uint32_t spiClockHz);

  void begin(uint8_t sckPin, uint8_t misoPin, uint8_t mosiPin);
  void reset();

  // Configures both receive buffers, enables RX interrupts and requests silent
  // Listen-Only mode. The caller performs the non-blocking settling wait.
  bool configureListenOnly(uint32_t bitrate, uint32_t oscillatorHz);
  bool isListenOnly();

  uint8_t interruptFlags();
  uint8_t errorFlags();
  bool readFrame(uint8_t receiveBuffer, CanFrame& frame);
  void clearInterruptFlags(uint8_t mask);
  void clearReceiveOverflowFlags();

 private:
  struct BitTiming {
    uint8_t cnf1;
    uint8_t cnf2;
    uint8_t cnf3;
  };

  static bool lookupBitTiming(uint32_t bitrate, uint32_t oscillatorHz,
                              BitTiming& timing);

  uint8_t readRegister(uint8_t address);
  void readRegisters(uint8_t address, uint8_t* destination, size_t length);
  void writeRegister(uint8_t address, uint8_t value);
  void bitModify(uint8_t address, uint8_t mask, uint8_t value);
  void beginTransaction();
  void endTransaction();

  SPIClass& spi_;
  const uint8_t chipSelectPin_;
  const uint32_t spiClockHz_;
};

