# Serial Protocol Contract

## Version

Protocol version: `v1`

The startup marker is:

```text
#BOOT:AdvancedCANAnalyzer:v1
```

## Frame grammar

```text
frame   = type identifier ":" dlc ":" byte "," byte "," byte "," byte
          "," byte "," byte "," byte "," byte LF
type    = "S" | "E" | "R" | "X"
dlc     = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8"
byte    = 2HEXDIG
```

`S` and `R` use exactly three hexadecimal identifier digits. `E` and `X` use
exactly eight. All letters emitted by firmware are uppercase. The parser accepts
lowercase hexadecimal digits but validates field width and range.

| Type | Identifier form | Frame form |
| --- | --- | --- |
| `S` | `000` to `7FF` | Standard data |
| `E` | `00000000` to `1FFFFFFF` | Extended data |
| `R` | `000` to `7FF` | Standard remote |
| `X` | `00000000` to `1FFFFFFF` | Extended remote |

Examples:

```text
S123:8:00,10,20,30,40,50,60,70
E18DAF110:3:AA,BB,CC,00,00,00,00,00
R321:0:00,00,00,00,00,00,00,00
```

The eight payload fields are fixed. Fields above DLC are `00` and must not be
interpreted as bus data.

## Metadata grammar

Any line beginning with `#` is metadata. A v1 host must ignore unknown metadata
keys rather than treating them as malformed CAN frames.

```text
#CFG:bitrate=500000,oscillator=8000000,serial=921600,mode=listen-only
#STAT:ready=1,rx=1832,queue_drop=0,hw_overflow=0,bad=0
#FATAL:mcp2515_initialization_failed
```

| Counter | Meaning |
| --- | --- |
| `rx` | Frames successfully removed from MCP2515 receive buffers |
| `queue_drop` | Frames discarded because the ESP32 RAM queue was full |
| `hw_overflow` | Observed MCP2515 RX overflow events |
| `bad` | Frames rejected because DLC/buffer content was invalid |

## Compatibility rule

Changing delimiters, adding timestamps to data lines, removing fixed byte
fields, or reassigning a type letter requires a new protocol version and a
matching parser update. Metadata keys may be added within v1.

