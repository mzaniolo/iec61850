# IEC 61850 client layer — audit

Audit of the IEC 61850 client layer for bugs, protocol/spec violations, and
robustness problems. This repository implements the **client** only.

**Scope**

- Files: `iec61850.rs`, `iec61850/data.rs`, `iec61850/rcb.rs`,
  `iec61850/report.rs`, `iec61850/model.rs`.
- Excluded: file-transfer paths (`read_file`, `get_directory`) — not yet
  implemented.
- Method: read-and-reason audit. Wire-format claims were cross-checked against
  the MMS / IEC 61850 specifications; the deterministic findings (panics,
  rigid lengths) are demonstrable by inspection but were not triggered against
  a live IED.

**Status legend:** ☐ open · ☑ fixed

---

## Severity summary

| ID | Severity | File | Title | Status |
|------|----------|------|-------|--------|
| P0-1 | Critical | `data.rs` | FloatingPoint endianness + format byte wrong | ☑ |
| P0-2 | Critical | `data.rs` | UtcTime byte order wrong (little-endian) | ☑ |
| P1-1 | High | `data.rs` | TimeOfDay decode panics on short input | ☑ |
| P1-2 | High | `data.rs` | Bitstring padding derived from `capacity()` | ☑ |
| P1-3 | High | `rcb.rs` | RCB field-count discrimination too rigid | ☑ |
| P2-1 | Medium | `data.rs` | UtcTime TimeQuality discarded; fraction precision | ☐ |
| P2-2 | Medium | `report.rs` | Report field order untested against a capture | ☐ |
| P2-3 | Medium | `iec61850.rs` | `read_dataset` hardcodes `specification_with_result=false` | ☐ |
| P2-4 | Medium | `iec61850.rs` | `Iec61850ClientError` has no span-trace context | ☐ |
| P3-1 | Low | `model.rs` | Arrays of structures lose their array-ness | ☐ |
| P3-2 | Low | `model.rs` | Missing component name becomes empty-string node | ☐ |
| P3-3 | Low | `model.rs` | `IedModel::Display` swallows serde errors | ☐ |
| P3-4 | Low | `iec61850.rs` | `set_rcb_dataset` `DatSet` value format unverified | ☐ |

---

## P0 — Critical correctness (silently wrong values against real IEDs)

### P0-1 · `data.rs:171-184` · FloatingPoint endianness + format byte wrong  ☑ FIXED

> **Fixed:** decode now `f32::from_be_bytes`; encode writes `[8, be0..be3]`.
> Real-data tests added (`test_floating_point_big_endian`).


MMS `FloatingPoint` is an OCTET STRING whose **first octet is the exponent
width** (`8` for single precision, `11` for double), followed by the IEEE-754
value in **big-endian** order (IEC 9506-2 §14.4.2.2).

Current behavior:

- **Decode** (`TryFrom<FloatingPoint> for f32`): `f32::from_le_bytes(last 4)`
  reads **little-endian**, so every float read from a spec-compliant IED is
  byte-reversed.
- **Encode** (`From<f32> for FloatingPoint`): writes `[0, le0, le1, le2, le3]`
  — format byte **0** (should be `8`) and little-endian bytes. A compliant
  server may reject or misread it.

The encode/decode are self-consistent (little-endian both ways), so a
round-trip unit test passes — which is why the bug is currently masked.

**Fix:** decode with `f32::from_be_bytes`, validating/using the exponent-width
byte; encode `[8, be0, be1, be2, be3]` via `to_be_bytes`. Add a test using a
real captured value, not just a round-trip.

**Reference:** <https://ask.wireshark.org/question/24687/converting-floating-point-mms/>

### P0-2 · `data.rs:205-227, 246-266` · UtcTime byte order wrong (little-endian)  ☑ FIXED

> **Fixed:** decode/encode now big-endian for seconds and fraction. Also fixed
> a magnitude bug in the decode (it passed milliseconds-since-epoch to
> `from_unix_timestamp`, which expects seconds) — now uses
> `from_unix_timestamp(seconds) + Duration::milliseconds(...)`. Real-data tests
> added (`test_utc_time_big_endian_decode`, `test_utc_time_big_endian_round_trip`).


IEC 61850 `UtcTime` (8 octets) is **big-endian**: 4-octet SecondSinceEpoch,
3-octet FractionOfSecond, 1-octet TimeQuality.

Current behavior reads `i32::from_le_bytes` for the seconds and `[0, b4, b5,
b6]` little-endian for the fraction, and encodes with `to_le_bytes` — all
wrong byte order, so timestamps from real IEDs are wrong.

**Strong corroboration:** the sibling `TimeOfDay` / binary-time path correctly
uses `from_be_bytes` / `to_be_bytes` and has a passing real-data test
(`data.rs` `test_from_binary_time_to_offset_date_time`), while `UtcTime` uses
little-endian and is only tested with an all-zero value (endian-agnostic).

**Fix:** big-endian for seconds and fraction on both decode and encode; add a
real-data test.

**Reference:** <http://idahogray.github.io/blog/2016-10-06.html>

---

## P1 — Robustness (panics / model-load failures on valid input)

### P1-1 · `data.rs:268-286` · TimeOfDay decode can panic on short input  ☑ FIXED

> **Fixed:** the milliseconds field now uses `first_chunk().context(...)?` and
> the days field uses `get(..).context(...)?`, so a short value errors instead
> of panicking. Test: `test_time_of_day_short_input_errors_not_panics`.


`TryFrom<TimeOfDay> for OffsetDateTime` checks `value.0.len() == 6` only for
the day part, then unconditionally indexes `value.0[0]..value.0[3]` for the
milliseconds. A `binary_time` OCTET STRING shorter than 4 bytes
(malformed/hostile server) causes an **index-out-of-bounds panic** in the
read/report path. (UtcTime/FloatingPoint decode use `get` / `*_chunk` and are
bounds-safe; only this path indexes directly.)

**Fix:** bounds-check with `.get(..).context(MissingData)?` like the UtcTime
path.

### P1-2 · `data.rs:57-73, 76-84` · Bitstring padding derived from `capacity()`  ☑ FIXED

> **Fixed:** padding is now `((8 - len % 8) % 8)` from the logical bit length.
> Test asserts the padding value in `test_from_bitstring_to_bit_string`.


`From<BitString> for Bitstring` computes `padding = value.capacity() -
value.len()`. `capacity()` is an **allocation** detail, not the logical bit
count. Depending on the backing store this produces wrong padding, and the
inverse `From<Bitstring> for BitString` does `truncate(len - padding)`, which
can **underflow and panic** when re-encoding a decoded bitstring (e.g. writing
back an RCB attribute). It also breaks the derived `Eq` (equal bits but
different capacity compare unequal).

Report `meas_count` uses `count_ones` and is unaffected; the impact is on
write-back paths.

**Fix:** `padding = ((8 - len % 8) % 8) as u8`.

### P1-3 · `rcb.rs:273-287` · RCB field-count discrimination too rigid  ☑ FIXED

> **Fixed:** `from_data` now accepts 14/15 (buffered) and 11/12 (unbuffered);
> a trailing optional `Owner` attribute is dropped rather than failing the
> model load. Tests: `test_rcb_parses_without_owner`,
> `test_rcb_tolerates_trailing_owner`. (Owner is not yet modelled — see note.)


`ReportControlBlock::from_data` distinguishes buffered vs unbuffered by exactly
`len() == 14` / `11`. Real RCBs commonly expose an optional `Owner` attribute
(and buffered RCBs may carry more), making the count 15/12 →
`InvalidDataLength`. Because this runs inside `get_ied_model`, it aborts the
**entire model load** for an otherwise-valid IED.

**Fix:** parse positionally and tolerate trailing optional fields, or key off
the `RP`/`BR` marker plus a minimum length instead of exact equality.

---

## P2 — Robustness & completeness

### P2-1 · `data.rs:218-222, 253-254` · TimeQuality discarded; fraction precision

UtcTime quality bits (leap-second-known, clock-failure, not-synchronized) are
parsed into `_`-prefixed locals and dropped (`//TODO: Fix it`); encode
hardcodes quality `0x00`. The fraction divides by `16777` where the exact
factor is `2^24 / 1000 = 16777.216`, a minor precision loss. Quality matters
for SCADA — a not-synchronized timestamp should not be trusted silently.

**Fix:** surface quality on the timestamp representation.

### P2-2 · `report.rs:174-213` · Report field order untested against a capture

The parse order (inclusion → data-references → values → reasons, each sized by
`meas_count`) looks correct but has **no real-data test**. If the order is
wrong, every reported value shifts silently. Given P0-1/P0-2 hid in untested
paths, this warrants a capture-based regression test.

### P2-3 · `iec61850.rs:268` · `read_dataset` hardcodes `specification_with_result=false`

Carries `// TODO: Changing from false to true will break stuff. Investigate
why.` Positional mapping of results to dataset members is fragile and the TODO
flags an unresolved correctness question.

### P2-4 · `iec61850.rs:520-543` · `Iec61850ClientError` has no span-trace context

Unlike every error type in the MMS layer (which carries `SpanTraceWrapper`),
the IEC 61850 errors carry no context, so failures here lose the diagnostic
trail the lower layers establish.

---

## P3 — Minor

### P3-1 · `model.rs:197-208` · Arrays of structures lose their array-ness

`Node::to_nodes` only marks scalar element types with `[type]`; an array of
structures silently becomes a single `DataObject` with the array dimension
dropped.

### P3-2 · `model.rs:174, 213` · Missing component name becomes empty-string node

A component with no `component_name` becomes a node named `""` via
`unwrap_or_default()` rather than being skipped or reported.

### P3-3 · `model.rs:258-260` · `IedModel::Display` swallows serde errors

`Display` uses `serde_json::to_string(_pretty)(...).unwrap_or_default()`,
emitting an empty string on a serialization error instead of surfacing it.

### P3-4 · `iec61850.rs:381` · `set_rcb_dataset` `DatSet` value format unverified

`set_rcb_dataset` strips a leading `@` then writes the value; the exact `DatSet`
string format expected by servers should be confirmed against a real IED.

---

## Suggested fix order

1. **P0-1 + P0-2** together (`data.rs` endianness) with real-data round-trip
   tests.
2. **P1-1 + P1-2** (`data.rs` panic + padding).
3. **P1-3** (`rcb.rs` flexibility).
4. **P2** cluster.
5. **P3** cleanup.

The two P0s are the priority: they make float and UTC-timestamp reads silently
wrong against any real IED, and they are currently masked by self-consistent
little-endian-both-ways round-trip tests.
