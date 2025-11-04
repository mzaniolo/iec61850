# IEC 61850

A rust implementation of the IEC61850 protocol

## Stack

```mermaid
---
title: "MMS Stack"
config:
    packet:
        showBits: false
---
packet
+32: "Application Layer (MMS)"
+32: "ACSE (Association Control)"
+32: "Presentation Layer (ISO Presentation)"
+32: "Session Layer (ISO Session)"
+32: "Transport Layer (COTP)"
+32: "TCP"
```

### [ISO COTP Structure](https://datatracker.ietf.org/doc/html/rfc1006)

ref:

- <https://www.rfc-editor.org/rfc/rfc905.html>
- <https://datatracker.ietf.org/doc/html/rfc1006>

```mermaid
---
title: "TPKT"
---
packet
+8: "version"
+8: "Reserved"
+16: "Package lenght (in bytes)"
+32: "TPDU (variable lenght. From 7 to 65531 )"
```

The packed length includes the header. This means the maximum size of a TPDU is 65531.

TPDU types:

- CR - Connection Request
- CC - Connection Confirm
- DT - Data transfer

```mermaid
---
title: "CR"
---
packet
+8:  "LI"
+8:  "Type  0xe0"
+16: "DstRef - 0X0000"
+16: "SrcRef"
+8:  "Class - 0"
+8: "Option (variable)"
```

```mermaid
---
title: "CC"
---
packet
+8:  "LI"
+8:  "Type  0xd0"
+16: "DstRef - SrcRef from the rcv CR"
+16: "SrcRef"
+8:  "Class - 0"
+8: "Option (variable)"
```

For CR and CC, the LI is the length of the request discounting the LI itself. So, the option size is LI-6.

```mermaid
---
title: "DT"
---
packet
+8: "LI - Always 2"
+8: "Type  0xf0"
+8: "EOT - 0x80 or 0"
+8: "Data - (Variable)"
```

The size of the data is the TPKT package length - 4 (TPKT header) - 3 (DT TPDU header)

### ISO Session Structure

```mermaid
---
title: "SPDU Header"
---
packet
+8: "SI"
+8: "LI"
+24: "Body (variable)"
```

SPDU Identifiers

- Connect (CN): 0x0D
- Accept (AC): 0x0E
- Refuse: 0x0C
- Data (DT): 0x01
- Finish (FN): 0x09
- Disconnect (DN): 0x0A
- Abort (AB): 0x19
- Not finished: 0x08

```mermaid
---
title: "Connect SPDU body - Parameter group"
---
packet
+8: "PGI Code - 0x05"
+8: "Lenght of PIs"
+8: "Protocol options (PI) - 0x13"
+8: "Lenght"
+8: "Option value"
+8: "Version number PI - 0x16"
+8: "Lenght"
+8: "Version value - 0x02"
```

```mermaid
---
title: Connect SPDU body - Session req
---
packet
+8: "PI code - 0x14"
+8: "Lenght - 0x02"
+16: "requirements"
```

```mermaid
---
title: "Connect SPDU body - Calling session selector"
---
packet
+8: "PI code - 0x33"
+8: "Lenght - from 0 to 16"
+16: "selector values"
```

```text
SPDU
 ├─ SI (SPDU Identifier) - 1 byte
 ├─ LI (Length Indicator) - 1 byte
 └─ Body
     ├─ Parameter Groups (PGI)
     │   └─ Parameters (PI)
     │       └─ Parameter Values
     └─ User Data (optional)
```

Session requirements

```text
Bit Position | Hex Value | Functional Unit          | Description
-------------|-----------|--------------------------|---------------------------
Bit 0        | 0x0001    | Kernel                   | Basic session services (always required)
Bit 1        | 0x0002    | Half-Duplex (HDX)        | Half-duplex data transfer
Bit 2        | 0x0004    | Duplex (DUP)             | Full-duplex data transfer
Bit 3        | 0x0008    | Expedited Data           | Send urgent/expedited data
Bit 4        | 0x0010    | Minor Synchronize        | Minor sync points
Bit 5        | 0x0020    | Major Synchronize        | Major sync points
Bit 6        | 0x0040    | Resynchronize            | Session resynchronization
Bit 7        | 0x0080    | Activity Management      | Activity start/stop/resume
Bit 8        | 0x0100    | Negotiated Release       | Coordinated session release
Bit 9        | 0x0200    | Capability Data Exchange | Exchange capability info
Bit 10       | 0x0400    | Exceptions               | Exception reporting
Bit 11       | 0x0800    | Typed Data               | Typed data transfer
Bit 12-15    | Reserved  | -                        | Reserved for future use
```

asn1 lib: <https://github.com/librasn/rasn?tab=readme-ov-file>
asn1 classes def: <https://github.com/beanit/iec61850bean/blob/master/asn1/readme.txt>
asn1 from wireshark: <https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/mms/mms.asn>

<https://sislab.no/MMS_Notat.pdf>

| IEC61850 Obj | MMS Obj |
|--------------|---------|
| Server | VMD |
| LD | Domain|
| LN | NamedVariable |
| Data | NamedComponent |
| DataAttr | NamedComponent |
| DataSet | NamedVariableList |
