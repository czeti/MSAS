#!/usr/bin/env bash
set -euo pipefail

# --- Config ---
HOST="${MF_HOST:-192.168.8.210}"
USER="${MF_USER:-IBMUSER}"
PASS="${MF_PASS:-SYS1}"

ASM_PDS="${ASM_PDS:-IBMUSER.PROBES.ASM}"
OUT_BASE="${OUTPUT_DSN:-IBMUSER.MSAS.OUTPUT}"

LOCAL_TXT="${LOCAL_OUTPUT:-/tmp/test_output/hlasm_output.txt}"
LOCAL_LST="${LOCAL_LISTING:-/tmp/test_output/hlasm_listing.txt}"

PROBE="${1:-apf_check}"

# --- Member name sanitisation ---
MEMBER=$(printf "%s" "$PROBE" \
  | tr '[:lower:]' '[:upper:]' \
  | tr -d '_-' \
  | cut -c1-8)

PID_TAG=$(printf '%05d' $(( $$ % 99999 )))

OUT_DSN="${OUT_BASE}.${MEMBER}.P${PID_TAG}"
LST_DSN="${OUT_BASE}.${MEMBER}.P${PID_TAG}L"

SRC_FILE="probes/hlasm/${PROBE}.asm"
JCL_SRC="probes/jcl/RUN_HLASM.jcl"

OUT_DIR="$(dirname "$LOCAL_TXT")"

TMP_JCL="/tmp/jcl_${$}.tmp"
TMP_JCL_FILLED="/tmp/jcl_${$}.final"

BIN_OUT="${LOCAL_TXT%.txt}_raw.bin"
HEX_OUT="${LOCAL_TXT%.txt}_hex.txt"

mkdir -p "$OUT_DIR"
trap 'rm -f "$TMP_JCL" "$TMP_JCL_FILLED"' EXIT

# --- Prepare JCL ---
cp "$JCL_SRC" "$TMP_JCL"

sed \
  -e "s/%MEMBER%/${MEMBER}/g" \
  -e "s/%OUTPUT_DSN%/${OUT_DSN}/g" \
  -e "s/%LISTING_DSN%/${LST_DSN}/g" \
  "$TMP_JCL" > "$TMP_JCL_FILLED"

# --- FTP helpers ---
ftp_ascii() {
  ftp -inv "$HOST" <<EOF 2>&1 || true
user $USER $PASS
quote TYPE A
get "'$1'" "$2"
bye
EOF
}

ftp_binary() {
  ftp -inv "$HOST" <<EOF 2>&1 || true
user $USER $PASS
quote TYPE I
get "'$1'" "$2"
bye
EOF
}

ftp_remove() {
  ftp -inv "$HOST" <<EOF 2>&1 || true
user $USER $PASS
quote site filetype=seq
delete "'$1'"
bye
EOF
}

upload_ok() {
  grep -qi "Transfer completed" <<<"$1"
}

# --- EBCDIC decode ---
decode_data() {
  local in_bin="$1"
  local out_hex="$2"
  local rec_len="${3:-133}"

  python3 - "$in_bin" "$out_hex" "$rec_len" <<'PY'
import sys, pathlib, unicodedata

raw = pathlib.Path(sys.argv[1]).read_bytes()
hex_file = sys.argv[2]
lrecl = int(sys.argv[3])

VALID = (
    set(range(0xC1, 0xCA)) |
    set(range(0xD1, 0xDA)) |
    set(range(0xE2, 0xEA)) |
    set(range(0xF0, 0xFA)) |
    {0x40, 0x4B, 0x5B, 0x60, 0x7B, 0x7C}
)

if len(raw) % lrecl != 0:
    print(f"Warning: size {len(raw)} not aligned to LRECL={lrecl}", file=sys.stderr)

diag = []

for idx, off in enumerate(range(0, len(raw), lrecl), 1):
    rec = raw[off:off+lrecl]

    text = rec.decode('cp037', errors='replace')
    clean = ''.join(
        c if unicodedata.category(c)[0] not in ('C', 'Z') or c == ' '
        else '.'
        for c in text
    ).rstrip()

    print(clean)

    if "APF entry" in clean:
        dsn = rec[25:69]
        vol = rec[74:80]

        valid = all(b in VALID for b in dsn)

        diag.append(
            f"Record {idx}: DSN={dsn.hex()} VOL={vol.hex()} "
            f"VALID={'YES' if valid else 'NO (invalid bytes present)'}"
        )

pathlib.Path(hex_file).write_text("\n".join(diag) + "\n")
print(f"\n[hex output -> {hex_file}]", file=sys.stderr)
PY
}

# --- Upload ASM ---
echo "[Uploading] $PROBE -> $MEMBER"
echo "[Output DSN] $OUT_DSN"
echo "[Listing DSN] $LST_DSN"

TRIES=3
SUCCESS=0

for n in $(seq 1 $TRIES); do
  echo "Upload try $n/$TRIES"
  [ "$n" -gt 1 ] && sleep 3

  RESP=$(ftp -inv "$HOST" <<EOF 2>&1
user $USER $PASS
quote TYPE A
put $SRC_FILE "'$ASM_PDS($MEMBER)'"
bye
EOF
)

  echo "$RESP"

  if upload_ok "$RESP"; then
    SUCCESS=1
    break
  fi

  echo "Retrying..."
done

if [ "$SUCCESS" -ne 1 ]; then
  echo "Upload failed after $TRIES attempts"
  exit 1
fi

# --- Submit job ---
echo "[Submitting JCL]"
sleep 1

RESP=$(ftp -inv "$HOST" <<EOF 2>&1
user $USER $PASS
quote TYPE A
quote site filetype=jes
put "$TMP_JCL_FILLED"
bye
EOF
)

echo "$RESP"

JOBID=$(grep -oE 'JOB[0-9]+' <<<"$RESP" | head -1)

[ -z "$JOBID" ] && { echo "No JobID found"; exit 1; }

echo "Job: $JOBID"

# --- Listing poll ---
echo "[Waiting for listing]"

MAX=20
DELAY=5

for i in $(seq 1 $MAX); do
  echo "Listing check $i/$MAX"
  rm -f "$LOCAL_LST"

  ftp_ascii "$LST_DSN" "$LOCAL_LST" | tail -3

  if [ -s "$LOCAL_LST" ]; then
    echo "[Listing saved]"
    cat "$LOCAL_LST"

    ftp_remove "$LST_DSN"

    RC=$(grep -m1 'Return Code' "$LOCAL_LST" | awk '{print $NF+0}')

    if [ "${RC:-0}" -gt 4 ]; then
      echo "Assembly error RC=$RC"
      exit 1
    fi

    break
  fi

  sleep "$DELAY"
done

# --- Output poll ---
echo "[Waiting for output dataset]"

READY=0

for i in $(seq 1 $MAX); do
  echo "Check $i/$MAX"
  rm -f "$BIN_OUT"

  ftp_binary "$OUT_DSN" "$BIN_OUT" | tail -3

  if [ -s "$BIN_OUT" ]; then
    ftp_remove "$OUT_DSN"
    READY=1
    break
  fi

  sleep "$DELAY"
done

if [ "$READY" -ne 1 ]; then
  echo "Timeout waiting for dataset $OUT_DSN"
  exit 1
fi

# --- Decode ---
echo "[Decoded output]"
decode_data "$BIN_OUT" "$HEX_OUT" 133 | tee "$LOCAL_TXT"

echo ""
echo "[Hex diagnostics]"
cat "$HEX_OUT"

echo ""
echo "If DSN validity shows NO, your APF source is likely non-standard."
echo "[Done]"
