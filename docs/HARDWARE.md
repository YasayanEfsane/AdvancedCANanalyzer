# Hardware Integration Notes

## Electrical boundary

The capture chain has three distinct layers:

1. ESP32 logic and SPI at 3.3 V.
2. MCP2515 CAN protocol controller at a verified logic voltage.
3. A CAN transceiver that converts TXCAN/RXCAN logic into CAN-H/CAN-L.

Do not collapse these layers conceptually. MCP2515 does not connect directly to
CAN-H or CAN-L, and a module carrying MCP2515 may contain a 5 V-only transceiver.

## Recommended prototype connection

| ESP32-WROOM pin | MCP2515 label | Requirement |
| --- | --- | --- |
| 3V3 | VCC | Only for a controller/module explicitly rated for 3.3 V operation |
| GND | GND | Common logic reference |
| GPIO 18 | SCK | SPI mode 0 clock |
| GPIO 23 | SI | MOSI |
| GPIO 19 | SO | MISO; must never exceed ESP32 I/O voltage |
| GPIO 27 | CS | Active-low chip select |
| GPIO 26 | INT | Active-low interrupt; pull up to the correct logic rail |

For a bare SN65HVD230, connect MCP2515 TXCAN to D and RXCAN to R, supply both at
3.3 V, and route CAN-H/CAN-L as a twisted pair. Follow the transceiver datasheet
for RS/slope control and bypassing.

## Module checklist

Before applying power, identify:

- MCP2515 crystal marking: commonly `8.000` or `16.000`.
- Transceiver part number and its supply requirement.
- Whether MISO and INT can rise to 5 V.
- Whether a 120-ohm termination resistor or jumper is populated.
- Whether VCC powers both the controller and transceiver.
- Whether the board has adequate local decoupling.

A bidirectional level shifter is not automatically suitable for fast SPI.
Prefer a native 3.3 V design or properly selected unidirectional buffers.

## Vehicle connection checklist

1. Vehicle stationary, drivetrain disabled, charger disconnected unless its
   isolation is understood.
2. Correct service diagram available.
3. Breakout cable used; no loose probe wires in the connector.
4. CAN-H, CAN-L, and reference ground identified.
5. No added termination on an already terminated bus.
6. ESP32 powered from USB or a protected automotive supply.
7. Firmware built for the verified MCP oscillator and candidate bitrate.
8. Listen-only startup confirmed from `#CFG` and `#STAT`.

On a bench, Listen-Only mode does not acknowledge a transmitter. Provide a
separate ACK-capable node or configure the traffic generator for a suitable
no-ACK test mode; otherwise the transmitter may repeatedly retry one frame.

## Why the receive interrupt matters

MCP2515 owns two receive buffers. Its INT line remains asserted while an enabled
interrupt condition is pending. A falling edge wakes the ESP32 RX task; that task
then reads both buffer flags and drains both buffers. If another frame arrives
while INT remains low, the drain loop sees the newly set flag without requiring a
second edge. Serial output is deliberately excluded from this path.

## Throughput estimate

UART commonly transports ten line bits for each ASCII character. A typical
standard-frame line is roughly 31 characters, or about 310 serial bits. At
921600 baud, the theoretical ceiling is therefore below 3000 such lines per
second before USB-UART and software overhead. A fully saturated 500 kbit/s CAN
bus can exceed that depending on frame length. The queue absorbs bursts; it
cannot resolve a permanent rate mismatch.
