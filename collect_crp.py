#!/usr/bin/env python3
"""
Stage 1 -- capture APUF packets over UART (8-round frame, HNG -> GPK aggregator) and
optionally cross-check an exported Vivado ILA capture against them.

Default target: 10,000 packets x 8 rounds = 80,000 round records (CSV rows).

Design reference (tks_hng_gpk_aggregation / crp_logger):
    4 APUFs -> raw responses {R3,R2,R1,R0}
    HNG gate : A=R0 B=R1 C=R2 D=R3  ->  P=A, Q=B, R=A^B^C, S=((A^B)&C)^(A&B)^D
    GPK gate : L=P M=Q N=R O=S      ->  K3=L, K2=L^M, K1=(L&M)^N, K0=N^O   (round_key)

Frame (98 bytes, crc_logger.sv):
    [0:2]   A5 5A
    [2:4]   packet_sequence (big-endian)
    [4:92]  8 x 11-byte records: lfsr_state[4], challenge[4] (== lfsr), raw nibble {R3,R2,R1,R0},
            HNG nibble {P,Q,R,S}, round_key
    [92:96] response_32 field from the FPGA = 8 round keys, round 0 in bits 31:28
    [96:98] CRC-16/CCITT-FALSE over bytes [0:96]

ILA probe -> CSV column (what each ILA signal corresponds to in this CSV):
    probe0  lfsr_challenge          lfsr_state_hex / challenge_hex
    probe1  challenge_apuf0         lfsr ^ (q0_reg << 15)   -- q0_reg is NOT in the UART frame
    probe2  challenge_apuf1         == lfsr_challenge
    probe3  challenge_apuf2         == lfsr_challenge
    probe4  challenge_apuf3         lfsr ^ (q3_reg << 15)   -- q3_reg is NOT in the UART frame
    probe5  {R3,R2,R1,R0}           raw_response_nibble (+ apuf0..3_response)
    probe6  round_key               gpk_key
    probe7  response_28_in          response_28_in_hex / _binary  (rebuilt from earlier round keys)
    probe8  response_32 (core)      core_response_32_hex / _binary = {response_28_in, lfsr[31:28]}
    probe9  {q0_raw,q3_raw,q0_reg,q3_reg}   not logged over UART
    probe10 {rst,en,excite}         not logged (used by --ila-csv to pick the settled sample)
  response_32_hex / _binary in this CSV is the 8-round-key response the logger transmits,
  which is different from the core's response_32 (probe8).

Usage (PowerShell):
  python collect_crp_hng.py --port COM7 --packets 10000 --csv apuf_crps_10k.csv
  python collect_crp_hng.py --port COM7 --packets 10000 --ila-csv ila_export.csv
  python collect_crp_hng.py --compare-only --csv apuf_crps_10k.csv --ila-csv ila_export.csv
"""

from __future__ import annotations

import argparse
import csv
import re
import signal
import sys
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------- frame layout
MAGIC = b"\xA5\x5A"
RECORD_START = 4
RECORD_LEN = 11
RECORD_COUNT = 8
RESPONSE_LEN = 4
CRC_LEN = 2
RESPONSE_START = RECORD_START + RECORD_COUNT * RECORD_LEN   # 92
CRC_START = RESPONSE_START + RESPONSE_LEN                    # 96
PACKET_LEN = CRC_START + CRC_LEN                            # 98

assert RECORD_COUNT * 4 == 32

DEFAULT_PACKETS = 10_000
STOP_QUIET_SECONDS = 1.0
SEQ_MODULUS = 1 << 16
PROGRESS_EVERY = 1_000
MISMATCH_PRINT_LIMIT = 10

COLUMNS = [
    "packet_sequence", "round_index_0based",
    "lfsr_state_binary", "challenge_hold_binary", "lfsr_state_hex", "challenge_hex",
    "apuf0_response", "apuf1_response", "apuf2_response", "apuf3_response",
    "raw_response_nibble",
    "hng_input_a", "hng_input_b", "hng_input_c", "hng_input_d",
    "hng_p", "hng_q", "hng_r", "hng_s", "hng_nibble",
    "gpk_l", "gpk_m", "gpk_n", "gpk_o",
    "gpk_o1", "gpk_o2", "gpk_o3", "gpk_o4", "gpk_key",
    "response_28_in_binary", "response_28_in_hex",
    "core_response_32_binary", "core_response_32_hex",
    "response_32_binary", "response_32_hex",
    "crc16",
]

stop_requested = False
stop_command_sent = False
active_serial = None


# ---------------------------------------------------------------- software models
def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def lfsr_advance(x: int, n: int = 1) -> int:
    """lfsr_32: taps 31, 21, 1, 0, shift left."""
    for _ in range(n):
        x = ((x << 1) & 0xFFFFFFFF) | (((x >> 31) ^ (x >> 21) ^ (x >> 1) ^ x) & 1)
    return x


def hng_model(raw: int) -> int:
    """HNG gate, A=R0 B=R1 C=R2 D=R3 -> nibble {P,Q,R,S} (P = bit 3)."""
    a, b, c, d = raw & 1, (raw >> 1) & 1, (raw >> 2) & 1, (raw >> 3) & 1
    p, q = a, b
    r = a ^ b ^ c
    s = ((a ^ b) & c) ^ (a & b) ^ d
    return (p << 3) | (q << 2) | (r << 1) | s


def gpk_model(nib: int) -> int:
    """GPK gate, L,M,N,O = nibble bits 3..0 -> round_key {K3,K2,K1,K0}."""
    l, m, n, o = (nib >> 3) & 1, (nib >> 2) & 1, (nib >> 1) & 1, nib & 1
    return (l << 3) | ((l ^ m) << 2) | (((l & m) ^ n) << 1) | (n ^ o)


def aggregate_model(raw: int) -> int:
    return gpk_model(hng_model(raw))


def reconstruct_response32(keys) -> int:
    if len(keys) != RECORD_COUNT:
        raise ValueError(f"Expected {RECORD_COUNT} key nibbles, got {len(keys)}")
    value = 0
    for key in keys:
        value = (value << 4) | (key & 0x0F)
    return value


# ---------------------------------------------------------------- serial helpers
def request_stop():
    global stop_command_sent
    if active_serial is not None and not stop_command_sent:
        try:
            active_serial.write(b"S")
            active_serial.flush()
            stop_command_sent = True
        except Exception as exc:
            print(f"Could not send stop command: {exc}", file=sys.stderr)


def handle_sigint(_signum, _frame):
    global stop_requested
    stop_requested = True
    request_stop()


def read_exact(ser, count: int, timeout_seconds: float = 5.0) -> bytes:
    result = bytearray()
    deadline = time.monotonic() + timeout_seconds
    while len(result) < count:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"Timed out after receiving {len(result)}/{count} packet bytes")
        chunk = ser.read(count - len(result))
        if chunk:
            result.extend(chunk)
    return bytes(result)


def read_packet(ser) -> Optional[bytes]:
    """Scan for A5 5A then read one fixed-length packet; None after a quiet interval on shutdown."""
    previous = None
    last_activity = time.monotonic()
    while True:
        byte = ser.read(1)
        now = time.monotonic()
        if byte:
            last_activity = now
            value = byte[0]
            if previous == 0xA5 and value == 0x5A:
                return MAGIC + read_exact(ser, PACKET_LEN - 2)
            previous = value
        elif stop_requested and (now - last_activity) >= STOP_QUIET_SECONDS:
            return None


# ---------------------------------------------------------------- packet parsing
def parse_packet(packet: bytes):
    """Return (sequence, response32_reconstructed, response32_fpga, rows, model_flags).

    model_flags is a list of (hng_ok, key_ok) per round: the logged HNG nibble / round key
    compared with the software HNG -> GPK model run on the logged raw responses.
    """
    if len(packet) != PACKET_LEN:
        raise ValueError(f"Wrong packet length: {len(packet)} (expected {PACKET_LEN})")
    if packet[:2] != MAGIC:
        raise ValueError("Invalid packet header")

    received_crc = (packet[CRC_START] << 8) | packet[CRC_START + 1]
    calculated_crc = crc16_ccitt_false(packet[:CRC_START])
    if received_crc != calculated_crc:
        raise ValueError(f"CRC mismatch: received 0x{received_crc:04X}, calculated 0x{calculated_crc:04X}")

    sequence = (packet[2] << 8) | packet[3]
    fpga_response32 = int.from_bytes(packet[RESPONSE_START:RESPONSE_START + RESPONSE_LEN], "big")

    keys = [packet[RECORD_START + n * RECORD_LEN + 10] & 0x0F for n in range(RECORD_COUNT)]
    response32 = reconstruct_response32(keys)

    rows, flags = [], []
    key_accum = 0     # mirrors crp_logger key_accum: cleared at packet start, shifts in one key per round
    for round_number in range(RECORD_COUNT):
        offset = RECORD_START + round_number * RECORD_LEN
        lfsr_state = int.from_bytes(packet[offset:offset + 4], "big")
        challenge = int.from_bytes(packet[offset + 4:offset + 8], "big")
        raw = packet[offset + 8] & 0x0F
        hng = packet[offset + 9] & 0x0F
        key = packet[offset + 10] & 0x0F

        r0, r1, r2, r3 = (raw >> 0) & 1, (raw >> 1) & 1, (raw >> 2) & 1, (raw >> 3) & 1
        p, q, r, s = (hng >> 3) & 1, (hng >> 2) & 1, (hng >> 1) & 1, hng & 1

        # What the core (and the ILA) saw this round:
        response_28_in = key_accum & 0x0FFFFFFF                       # probe7
        core_response_32 = (response_28_in << 4) | (lfsr_state >> 28)  # probe8

        flags.append((hng_model(raw) == hng, aggregate_model(raw) == key))

        rows.append({
            "packet_sequence": sequence,
            "round_index_0based": round_number,
            "lfsr_state_binary": f"{lfsr_state:032b}",
            "challenge_hold_binary": f"{challenge:032b}",
            "lfsr_state_hex": f"0x{lfsr_state:08X}",
            "challenge_hex": f"0x{challenge:08X}",
            "apuf0_response": r0, "apuf1_response": r1,
            "apuf2_response": r2, "apuf3_response": r3,
            "raw_response_nibble": f"{raw:04b}",
            "hng_input_a": r0, "hng_input_b": r1, "hng_input_c": r2, "hng_input_d": r3,
            "hng_p": p, "hng_q": q, "hng_r": r, "hng_s": s,
            "hng_nibble": f"{hng:04b}",
            "gpk_l": p, "gpk_m": q, "gpk_n": r, "gpk_o": s,      # HNG P,Q,R,S feed GPK L,M,N,O
            "gpk_o1": (key >> 3) & 1, "gpk_o2": (key >> 2) & 1,
            "gpk_o3": (key >> 1) & 1, "gpk_o4": key & 1,
            "gpk_key": f"{key:04b}",
            "response_28_in_binary": f"{response_28_in:028b}",
            "response_28_in_hex": f"0x{response_28_in:07X}",
            "core_response_32_binary": f"{core_response_32:032b}",
            "core_response_32_hex": f"0x{core_response_32:08X}",
            "response_32_binary": f"{response32:032b}",
            "response_32_hex": f"0x{response32:08X}",
            "crc16": f"0x{received_crc:04X}",
        })
        key_accum = ((key_accum << 4) | key) & 0xFFFFFFFF
    return sequence, response32, fpga_response32, rows, flags


# ---------------------------------------------------------------- ILA cross-check
def _parse_int(text: str, radix: str) -> Optional[int]:
    t = text.strip().replace("_", "")
    if not t:
        return None
    try:
        return int(t, {"hex": 16, "bin": 2, "dec": 10}[radix])
    except ValueError:
        return None


def load_ila_csv(path: Path, radix: str):
    """Return list of samples, each {probe_index: int}. Matches headers on 'probeN'."""
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader)
        cols = {}
        for i, name in enumerate(header):
            m = re.search(r"probe(\d+)", name)
            if m:
                cols[int(m.group(1))] = i
        missing = [p for p in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10) if p not in cols]
        if missing:
            raise SystemExit(
                f"ILA CSV is missing columns for probes {missing}. Headers found: {header}\n"
                "Headers must contain 'probe0' ... 'probe10' (the default names of the ILA ports).")
        samples = []
        for row in reader:
            rec = {p: _parse_int(row[i], radix) if i < len(row) else None for p, i in cols.items()}
            if any(v is None for v in rec.values()):
                continue          # radix/label rows or blanks
            samples.append(rec)
    return samples


def compare_with_ila(uart_rows, ila_path: Path, radix: str):
    samples = load_ila_csv(ila_path, radix)
    print("\n" + "=" * 70)
    print(f"ILA cross-check: {len(samples):,} ILA samples from {ila_path}")
    print("=" * 70)
    if not samples:
        print("  No numeric samples found (check --ila-radix; Vivado exports in the radix shown in the waveform).")
        return

    # UART side, indexed by LFSR state.
    uart = {}
    for r in uart_rows:
        uart.setdefault(int(r["lfsr_state_hex"], 16), []).append(r)

    # ILA side: group consecutive samples with the same lfsr_challenge (= one round), and use the
    # last sample with excite=1: by then the race is done and the arbiter outputs are settled.
    groups, cur = [], [samples[0]]
    for s in samples[1:]:
        if s[0] == cur[-1][0]:
            cur.append(s)
        else:
            groups.append(cur); cur = [s]
    groups.append(cur)

    rounds_used = skipped_incomplete = skipped_no_excite = 0
    internal = dict(key_vs_model=0, apuf12=0, apuf0_q=0, apuf3_q=0, r32=0)
    not_found = ambiguous = 0
    cmp_fields = dict(raw=0, key=0, r28=0, r32=0, all=0)
    mism_print = 0
    for gi, g in enumerate(groups):
        exc = [s for s in g if s[10] & 1]
        if not exc:
            skipped_no_excite += 1
            continue
        if gi == len(groups) - 1 and (g[-1][10] & 1):
            skipped_incomplete += 1     # capture ended during this round's race
            continue
        s = exc[-1]
        rounds_used += 1
        lfsr, raw, key, r28, r32 = s[0], s[5] & 0xF, s[6] & 0xF, s[7] & 0x0FFFFFFF, s[8]
        q0_reg, q3_reg = (s[9] >> 1) & 1, s[9] & 1

        # internal consistency of the ILA capture itself
        internal["key_vs_model"] += aggregate_model(raw) == key
        internal["apuf12"] += (s[2] == lfsr and s[3] == lfsr)
        internal["apuf0_q"] += (s[1] == (lfsr ^ (q0_reg << 15)))
        internal["apuf3_q"] += (s[4] == (lfsr ^ (q3_reg << 15)))
        internal["r32"] += (r32 == ((r28 << 4) | (lfsr >> 28)))

        # compare with the UART capture of the same LFSR state
        match = uart.get(lfsr)
        if not match:
            not_found += 1
            continue
        if len(match) > 1:
            ambiguous += 1
        u = match[0]
        ok_raw = int(u["raw_response_nibble"], 2) == raw
        ok_key = int(u["gpk_key"], 2) == key
        ok_r28 = int(u["response_28_in_hex"], 16) == r28
        ok_r32 = int(u["core_response_32_hex"], 16) == r32
        cmp_fields["raw"] += ok_raw; cmp_fields["key"] += ok_key
        cmp_fields["r28"] += ok_r28; cmp_fields["r32"] += ok_r32
        cmp_fields["all"] += (ok_raw and ok_key and ok_r28 and ok_r32)
        if not (ok_raw and ok_key and ok_r28 and ok_r32) and mism_print < 10:
            mism_print += 1
            print(f"  mismatch lfsr=0x{lfsr:08X} (UART seq {u['packet_sequence']} round {u['round_index_0based']}): "
                  f"raw ILA {raw:04b} UART {u['raw_response_nibble']} | key ILA {key:04b} UART {u['gpk_key']} | "
                  f"r28 {'ok' if ok_r28 else 'DIFF'} | r32 {'ok' if ok_r32 else 'DIFF'}")

    compared = rounds_used - not_found
    print(f"  ILA rounds analysed        : {rounds_used}  (skipped: {skipped_no_excite} with no excite, "
          f"{skipped_incomplete} cut off at end of capture)")
    print("\n  ILA self-consistency (against the RTL equations):")
    print(f"    round_key == HNG->GPK model of probe5    : {internal['key_vs_model']}/{rounds_used}")
    print(f"    challenge_apuf1 == challenge_apuf2 == lfsr: {internal['apuf12']}/{rounds_used}")
    print(f"    challenge_apuf0 == lfsr ^ (q0_reg << 15)  : {internal['apuf0_q']}/{rounds_used}")
    print(f"    challenge_apuf3 == lfsr ^ (q3_reg << 15)  : {internal['apuf3_q']}/{rounds_used}")
    print(f"    response_32 == {{response_28_in, lfsr[31:28]}}: {internal['r32']}/{rounds_used}")
    print(f"\n  ILA vs UART (matched on lfsr_challenge): {compared} rounds found in the UART capture, "
          f"{not_found} not found")
    if compared:
        print(f"    raw responses  agree : {cmp_fields['raw']}/{compared}")
        print(f"    round_key      agrees: {cmp_fields['key']}/{compared}")
        print(f"    response_28_in agrees: {cmp_fields['r28']}/{compared}")
        print(f"    core response_32     : {cmp_fields['r32']}/{compared}")
        print(f"    all four agree       : {cmp_fields['all']}/{compared}")
    if ambiguous:
        print(f"  note: {ambiguous} LFSR states appeared more than once in the UART capture (first one used)")
    print("  Note: raw responses can legitimately differ between two runs (PUF noise, and the TKS feedback\n"
          "  path makes later rounds depend on earlier ones). The deterministic fields -- lfsr, the HNG/GPK\n"
          "  outputs given the raw bits, and response_28_in given the earlier keys -- should always agree.")


# ---------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--csv", "--out", dest="csv", default="apuf_crps_10k.csv", help="CSV output path")
    parser.add_argument("--raw", default="raw_packets_10k.bin", help="raw packet dump path")
    parser.add_argument("--packets", "--n", dest="packets", type=int, default=DEFAULT_PACKETS,
                        help="VALID packets to collect (default 10,000 = 80,000 round records); 0 = until Ctrl+C")
    parser.add_argument("--ila-csv", default=None, help="exported Vivado ILA CSV to cross-check against the capture")
    parser.add_argument("--ila-radix", choices=["hex", "bin", "dec"], default="hex",
                        help="radix of the values in the ILA CSV (default hex)")
    parser.add_argument("--compare-only", action="store_true",
                        help="skip UART collection; compare an existing --csv against --ila-csv")
    args = parser.parse_args()

    csv_path = Path(args.csv)

    if args.compare_only:
        if not args.ila_csv:
            sys.exit("--compare-only needs --ila-csv")
        with csv_path.open(newline="", encoding="utf-8") as f:
            uart_rows = list(csv.DictReader(f))
        compare_with_ila(uart_rows, Path(args.ila_csv), args.ila_radix)
        return

    try:
        import serial
    except ImportError as exc:
        raise SystemExit("pyserial is required: python -m pip install pyserial") from exc

    global stop_requested, stop_command_sent, active_serial
    signal.signal(signal.SIGINT, handle_sigint)
    raw_path = Path(args.raw)

    packets_attempted = valid_count = invalid_count = timeout_count = 0
    discarded_extra = duplicate_count = response_mismatch_count = 0
    hng_model_bad = key_model_bad = lfsr_step_bad = lfsr_step_pairs = 0
    last_sequence = None
    last_lfsr = None
    seen_this_cycle = set()
    all_rows = []

    print("=" * 70)
    print("Stage 1 -- APUF UART capture (8-round frame, HNG -> GPK)")
    print(f"  port / baud     : {args.port} / {args.baud}")
    print(f"  frame           : {PACKET_LEN} bytes = 4 header + {RECORD_COUNT} x {RECORD_LEN} records "
          f"+ {RESPONSE_LEN} response + {CRC_LEN} CRC")
    if args.packets:
        print(f"  target          : {args.packets:,} packets x {RECORD_COUNT} rounds = "
              f"{args.packets * RECORD_COUNT:,} round records")
        print(f"  UART time (min) : about {args.packets * PACKET_LEN * 10 / args.baud:,.0f} s")
    else:
        print("  target          : continuous (Ctrl+C to stop)")
    print(f"  csv / raw       : {csv_path} / {raw_path}")
    print("=" * 70)
    print("Sending G to start continuous collection. Press Ctrl+C to stop gracefully.\n")

    t_start = time.monotonic()
    with serial.Serial(port=args.port, baudrate=args.baud, bytesize=serial.EIGHTBITS,
                       parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                       timeout=0.25, write_timeout=2) as ser, \
            csv_path.open("w", newline="", encoding="utf-8") as csv_file, \
            raw_path.open("wb") as raw_file:

        active_serial = ser
        writer = csv.DictWriter(csv_file, fieldnames=COLUMNS)
        writer.writeheader()
        csv_file.flush()
        time.sleep(0.15)
        ser.reset_input_buffer()
        ser.write(b"G")
        ser.flush()

        try:
            while True:
                if args.packets and valid_count >= args.packets and not stop_requested:
                    stop_requested = True
                    request_stop()
                try:
                    packet = read_packet(ser)
                except TimeoutError as exc:
                    timeout_count += 1
                    print(f"Timeout waiting for packet body: {exc}", file=sys.stderr)
                    continue
                if packet is None:
                    if stop_requested:
                        break
                    continue

                if args.packets and valid_count >= args.packets:
                    discarded_extra += 1      # in flight when the stop command was processed
                    continue

                packets_attempted += 1
                raw_file.write(packet)
                try:
                    sequence, response32, fpga_response32, rows, flags = parse_packet(packet)
                except ValueError as exc:
                    invalid_count += 1
                    print(f"Rejected packet #{packets_attempted}: {exc}", file=sys.stderr)
                    continue

                if response32 != fpga_response32:
                    response_mismatch_count += 1
                    if response_mismatch_count <= MISMATCH_PRINT_LIMIT:
                        print(f"Warning: response32 mismatch in packet seq {sequence}: reconstructed "
                              f"0x{response32:08X} vs FPGA field 0x{fpga_response32:08X}", file=sys.stderr)

                contiguous = last_sequence is not None and sequence == (last_sequence + 1) % SEQ_MODULUS
                if last_sequence is not None and sequence == 0 and last_sequence == SEQ_MODULUS - 1:
                    seen_this_cycle.clear()
                elif sequence in seen_this_cycle:
                    duplicate_count += 1
                    print(f"Warning: duplicate sequence {sequence} before a wrap", file=sys.stderr)
                seen_this_cycle.add(sequence)
                if last_sequence is not None and not contiguous:
                    print(f"Warning: packet sequence jumped from {last_sequence} to {sequence}", file=sys.stderr)
                last_sequence = sequence

                # software-model checks and LFSR stepping (one shift per round, also across packets)
                for (hng_ok, key_ok), row in zip(flags, rows):
                    hng_model_bad += not hng_ok
                    key_model_bad += not key_ok
                    lf = int(row["lfsr_state_hex"], 16)
                    if last_lfsr is not None and (row["round_index_0based"] != 0 or contiguous):
                        lfsr_step_pairs += 1
                        lfsr_step_bad += lfsr_advance(last_lfsr, 1) != lf
                    last_lfsr = lf

                writer.writerows(rows)
                csv_file.flush()
                all_rows.extend(rows)
                valid_count += 1

                if valid_count % PROGRESS_EVERY == 0:
                    elapsed = time.monotonic() - t_start
                    print(f"[{valid_count:>9,} / {args.packets or '?'}] attempted={packets_attempted:,}  "
                          f"invalid={invalid_count}  timeouts={timeout_count}  duplicates={duplicate_count}  "
                          f"resp_mismatch={response_mismatch_count}  elapsed={elapsed:,.1f}s  "
                          f"rate={valid_count / elapsed:,.1f} packets/s")
        finally:
            request_stop()
            active_serial = None

    elapsed = time.monotonic() - t_start
    completion = "COMPLETE" if (args.packets and valid_count >= args.packets) else \
                 ("INTERRUPTED (Ctrl+C)" if stop_requested else "STOPPED")

    print("\n" + "=" * 70)
    print("Stage 1 summary")
    print("=" * 70)
    print(f"  completion status     : {completion}")
    print(f"  elapsed time          : {elapsed:,.1f} s")
    print(f"  packets attempted     : {packets_attempted:,}")
    print(f"  valid packets saved   : {valid_count:,}  ({valid_count * RECORD_COUNT:,} round rows)")
    print(f"  invalid / timeouts    : {invalid_count:,} / {timeout_count:,}")
    print(f"  in-flight discarded   : {discarded_extra:,}")
    print(f"  duplicate sequences   : {duplicate_count:,}")
    print(f"  response32 mismatches : {response_mismatch_count:,}  (8 key nibbles vs FPGA's response field)")
    print(f"  HNG nibble != model   : {hng_model_bad:,} rounds")
    print(f"  round_key != HNG->GPK : {key_model_bad:,} rounds")
    print(f"  LFSR not 1 shift apart: {lfsr_step_bad:,} of {lfsr_step_pairs:,} consecutive rounds")
    if csv_path.exists():
        print(f"  csv file              : {csv_path}  ({csv_path.stat().st_size:,} bytes)")
    if raw_path.exists():
        print(f"  raw dump file         : {raw_path}  ({raw_path.stat().st_size:,} bytes)")
    if args.packets and valid_count < args.packets:
        print(f"\n  NOTE: stopped {args.packets - valid_count:,} packets short of the {args.packets:,} target.")

    if args.ila_csv:
        compare_with_ila(all_rows, Path(args.ila_csv), args.ila_radix)


if __name__ == "__main__":
    main()