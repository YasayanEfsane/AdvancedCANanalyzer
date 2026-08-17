#include "mcp2515.hpp"

#include <cstring>

namespace {

constexpr uint8_t kInstructionReset = 0xC0;
constexpr uint8_t kInstructionRead = 0x03;
constexpr uint8_t kInstructionWrite = 0x02;
constexpr uint8_t kInstructionBitModify = 0x05;

constexpr uint8_t kRegisterCanStat = 0x0E;
constexpr uint8_t kRegisterCanCtrl = 0x0F;
constexpr uint8_t kRegisterCnf3 = 0x28;
constexpr uint8_t kRegisterCnf2 = 0x29;
constexpr uint8_t kRegisterCnf1 = 0x2A;
constexpr uint8_t kRegisterCanInte = 0x2B;
constexpr uint8_t kRegisterCanIntf = 0x2C;
constexpr uint8_t kRegisterEflg = 0x2D;
constexpr uint8_t kRegisterRxb0Ctrl = 0x60;
constexpr uint8_t kRegisterRxb0Sidh = 0x61;
constexpr uint8_t kRegisterRxb1Ctrl = 0x70;
constexpr uint8_t kRegisterRxb1Sidh = 0x71;

constexpr uint8_t kOperationModeMask = 0xE0;
constexpr uint8_t kListenOnlyMode = 0x60;
constexpr uint8_t kReceiveAnyMessage = 0x60;
constexpr uint8_t kRolloverEnable = 0x04;
constexpr uint8_t kReceiveRtr = 0x08;
constexpr uint8_t kExtendedId = 0x08;
constexpr uint8_t kDlcMask = 0x0F;
constexpr uint8_t kRx0Overflow = 0x40;
constexpr uint8_t kRx1Overflow = 0x80;

}  // namespace

Mcp2515::Mcp2515(SPIClass& spi, const uint8_t chipSelectPin,
                 const uint32_t spiClockHz)
    : spi_(spi),
      chipSelectPin_(chipSelectPin),
      spiClockHz_(spiClockHz) {}

void Mcp2515::begin(const uint8_t sckPin, const uint8_t misoPin,
                    const uint8_t mosiPin) {
  pinMode(chipSelectPin_, OUTPUT);
  digitalWrite(chipSelectPin_, HIGH);
  spi_.begin(sckPin, misoPin, mosiPin, chipSelectPin_);
}

void Mcp2515::beginTransaction() {
  // MCP2515 uses SPI mode 0 and samples MSB first. Eight MHz stays below the
  // controller's 10 MHz maximum and gives comfortable margin on jumper wires.
  spi_.beginTransaction(SPISettings(spiClockHz_, MSBFIRST, SPI_MODE0));
  digitalWrite(chipSelectPin_, LOW);
}

void Mcp2515::endTransaction() {
  digitalWrite(chipSelectPin_, HIGH);
  spi_.endTransaction();
}

void Mcp2515::reset() {
  beginTransaction();
  spi_.transfer(kInstructionReset);
  endTransaction();
}

uint8_t Mcp2515::readRegister(const uint8_t address) {
  beginTransaction();
  spi_.transfer(kInstructionRead);
  spi_.transfer(address);
  const uint8_t value = spi_.transfer(0x00);
  endTransaction();
  return value;
}

void Mcp2515::readRegisters(const uint8_t address, uint8_t* destination,
                            const size_t length) {
  beginTransaction();
  spi_.transfer(kInstructionRead);
  spi_.transfer(address);
  for (size_t index = 0; index < length; ++index) {
    destination[index] = spi_.transfer(0x00);
  }
  endTransaction();
}

void Mcp2515::writeRegister(const uint8_t address, const uint8_t value) {
  beginTransaction();
  spi_.transfer(kInstructionWrite);
  spi_.transfer(address);
  spi_.transfer(value);
  endTransaction();
}

void Mcp2515::bitModify(const uint8_t address, const uint8_t mask,
                        const uint8_t value) {
  beginTransaction();
  spi_.transfer(kInstructionBitModify);
  spi_.transfer(address);
  spi_.transfer(mask);
  spi_.transfer(value);
  endTransaction();
}

bool Mcp2515::lookupBitTiming(const uint32_t bitrate,
                              const uint32_t oscillatorHz,
                              BitTiming& timing) {
  // These CNF triplets are the established MCP2515 timing values for the four
  // supported crystal/bitrate combinations. Restricting the table prevents a
  // plausible-looking but invalid compile-time selection from reaching a car.
  if (oscillatorHz == 8'000'000UL && bitrate == 500'000UL) {
    timing = {0x00, 0x90, 0x82};
    return true;
  }
  if (oscillatorHz == 8'000'000UL && bitrate == 250'000UL) {
    timing = {0x00, 0xB1, 0x85};
    return true;
  }
  if (oscillatorHz == 16'000'000UL && bitrate == 500'000UL) {
    timing = {0x00, 0xF0, 0x86};
    return true;
  }
  if (oscillatorHz == 16'000'000UL && bitrate == 250'000UL) {
    timing = {0x41, 0xF1, 0x85};
    return true;
  }
  return false;
}

bool Mcp2515::configureListenOnly(const uint32_t bitrate,
                                  const uint32_t oscillatorHz) {
  BitTiming timing{};
  if (!lookupBitTiming(bitrate, oscillatorHz, timing)) {
    return false;
  }

  // RESET leaves the MCP2515 in Configuration mode. CNF registers are writable
  // only there. RXB0 rollover allows RXB1 to catch a frame when RXB0 is full.
  writeRegister(kRegisterCnf1, timing.cnf1);
  writeRegister(kRegisterCnf2, timing.cnf2);
  writeRegister(kRegisterCnf3, timing.cnf3);
  writeRegister(kRegisterRxb0Ctrl,
                kReceiveAnyMessage | kRolloverEnable);
  writeRegister(kRegisterRxb1Ctrl, kReceiveAnyMessage);

  writeRegister(kRegisterCanIntf, 0x00);
  clearReceiveOverflowFlags();

  // INT becomes active-low for either full receive buffer or an error. The GPIO
  // ISR only wakes a task; all SPI work remains outside interrupt context.
  writeRegister(kRegisterCanInte,
                kRx0Interrupt | kRx1Interrupt | kErrorInterrupt);
  bitModify(kRegisterCanCtrl, kOperationModeMask, kListenOnlyMode);
  return true;
}

bool Mcp2515::isListenOnly() {
  return (readRegister(kRegisterCanStat) & kOperationModeMask) ==
         kListenOnlyMode;
}

uint8_t Mcp2515::interruptFlags() {
  return readRegister(kRegisterCanIntf);
}

uint8_t Mcp2515::errorFlags() {
  return readRegister(kRegisterEflg);
}

void Mcp2515::clearInterruptFlags(const uint8_t mask) {
  bitModify(kRegisterCanIntf, mask, 0x00);
}

void Mcp2515::clearReceiveOverflowFlags() {
  bitModify(kRegisterEflg, kRx0Overflow | kRx1Overflow, 0x00);
}

bool Mcp2515::readFrame(const uint8_t receiveBuffer, CanFrame& frame) {
  if (receiveBuffer > 1) {
    return false;
  }

  const uint8_t sidhRegister =
      receiveBuffer == 0 ? kRegisterRxb0Sidh : kRegisterRxb1Sidh;
  const uint8_t ctrlRegister =
      receiveBuffer == 0 ? kRegisterRxb0Ctrl : kRegisterRxb1Ctrl;
  const uint8_t interruptMask =
      receiveBuffer == 0 ? kRx0Interrupt : kRx1Interrupt;

  // SIDH, SIDL, EID8, EID0, DLC and all eight data bytes are contiguous.
  // One burst transaction minimizes the time before the hardware buffer can be
  // released for the next frame.
  uint8_t raw[13]{};
  readRegisters(sidhRegister, raw, sizeof(raw));

  frame = {};
  frame.extended = (raw[1] & kExtendedId) != 0;
  if (frame.extended) {
    frame.id = (static_cast<uint32_t>(raw[0]) << 21U) |
               (static_cast<uint32_t>(raw[1] & 0xE0U) << 13U) |
               (static_cast<uint32_t>(raw[1] & 0x03U) << 16U) |
               (static_cast<uint32_t>(raw[2]) << 8U) | raw[3];
  } else {
    frame.id = (static_cast<uint32_t>(raw[0]) << 3U) | (raw[1] >> 5U);
  }

  frame.dlc = raw[4] & kDlcMask;
  frame.remote = (readRegister(ctrlRegister) & kReceiveRtr) != 0;
  if (frame.dlc > 8) {
    clearInterruptFlags(interruptMask);
    return false;
  }

  if (!frame.remote) {
    std::memcpy(frame.data, &raw[5], frame.dlc);
  }
  clearInterruptFlags(interruptMask);
  return true;
}

