#!/usr/bin/bash
set -e

HOST="${MF_HOST:-192.168.8.210}"
USER="${MF_USER:-IBMUSER}"
PASS="${MF_PASS:-SYS1}"
ASM_PDS="${ASM_PDS:-IBMUSER.PROBES.ASM}"
OUTPUT_DSN_BASE="${OUTPUT_DSN:-IBMUSER.MSAS.OUTPUT}"
LOCAL_OUTPUT="${LOCAL_OUTPUT:-/tmp/test_output/hlasm_output.txt}"
LOCAL_LISTING="${LOCAL_LISTING:-/tmp/test_output/hlasm_listing.txt}"

PROBE_NAME="${1:-apf_check}"

MEMBER=$(echo "$PROBE_NAME" \
  | tr '[:lower:]' '[:upper:]' \
  | tr -d '_-' \
  | cut -c1-8)

PID_SUFFIX=$(printf '%05d' $(( $$ % 99999 )))
OUTPUT_DSN="${OUTPUT_DSN_BASE}.${MEMBER}.P${PID_SUFFIX}"
LISTING_DSN="${OUTPUT_DSN_BASE}.${MEMBER}.P${PID_SUFFIX}L"

PROBE_LOCAL="probes/hlasm/${PROBE_NAME}.asm"
JCL_TEMPLATE="probes/jcl/RUN_HLASM.jcl"
OUTPUT_DIR="$(dirname "$LOCAL_OUTPUT")"
TMP_JCL="/tmp/run_hlasm_$$.jcl"
TMP_JCL_SUBST="/tmp/run_hlasm_subst_$$.jcl"
LOCAL_OUTPUT_BIN="${LOCAL_OUTPUT%.txt}_raw.bin"
LOCAL_OUTPUT_HEX="${LOCAL_OUTPUT%.txt}_hex.txt"

mkdir -p "$OUTPUT_DIR"
trap 'rm -f "$TMP_JCL" "$TMP_JCL_SUBST"' EXIT

cp "$JCL_TEMPLATE" "$TMP_JCL"

sed \
  -e "s/%MEMBER%/${MEMBER}/g" \
  -e "s/%OUTPUT_DSN%/${OUTPUT_DSN}/g" \
  -e "s/%LISTING_DSN%/${LISTING_DSN}/g" \
  "$TMP_JCL" > "$TMP_JCL_SUBST"

upload_succeeded() { echo "$1" | grep -qi "Transfer completed"; }

ftp_get_ascii() {
  ftp -inv "$HOST" 2>&1 <<FTPEOF || true
user $USER $PASS
quote TYPE A
get "'$1'" "$2"
bye
FTPEOF
}

ftp_get_binary() {
  ftp -inv "$HOST" 2>&1 <<FTPEOF || true
user $USER $PASS
quote TYPE I
get "'$1'" "$2"
bye
FTPEOF
}

ftp_delete_dataset() {
  ftp -inv "$HOST" 2>&1 <<FTPEOF || true
user $USER $PASS
quote site filetype=seq
delete "'$1'"
bye
FTPEOF
}

# Decode raw RECFM=FB EBCDIC binary from the mainframe
#
# note for future me: The output dataset is RECFM=FB LRECL=133, written by the
# HLASM probe as pure EBCDIC (cp037). binary FTP transfer gives me the raw
# bytes
decode_ebcdic_output() {
  local bin_file="$1"
  local hex_file="$2"
  local lrecl="${3:-133}"
  python3 - "$bin_file" "$hex_file" "$lrecl" <<'PYEOF'
import sys, pathlib, unicodedata

data   = pathlib.Path(sys.argv[1]).read_bytes()
hexout = sys.argv[2]
lrecl  = int(sys.argv[3])

# Valid EBCDIC bytes for dataset name chars (A-Z 0-9 @ # $ - . space)
VALID_DSN_EBCDIC = (
    set(range(0xC1, 0xCA)) |   # A-I
    set(range(0xD1, 0xDA)) |   # J-R
    set(range(0xE2, 0xEA)) |   # S-Z
    set(range(0xF0, 0xFA)) |   # 0-9
    {0x40, 0x4B, 0x5B, 0x60, 0x7B, 0x7C}  # space . $ - # @
)

if len(data) % lrecl != 0:
    print(f"WARNING: file size {len(data)} is not a multiple of LRECL={lrecl}",
          file=sys.stderr)

hex_lines = []

for rec_num, i in enumerate(range(0, len(data), lrecl), 1):
    raw = data[i:i+lrecl]

    # Decode cp037, replace any control/non-printable characters with '.'
    decoded = raw.decode('cp037', errors='replace')
    sanitised = ''.join(
        c if unicodedata.category(c)[0] not in ('C', 'Z') or c == ' '
        else '.'
        for c in decoded
    ).rstrip()

    print(sanitised)

    # --- Hex diagnostic ---
    # For APF entry lines, break out the fields:
    #   [0:25]  = "INFO: APF entry: dataset=" prefix (25 bytes)
    #   [25:69] = dataset name field (44 bytes)
    #   [69:74] = " vol=" (5 bytes)
    #   [74:80] = volser (6 bytes)
    if b'INFO: APF entry:' in raw[:30].decode('cp037', errors='replace').encode('utf-8', errors='replace') or \
       'APF entry' in sanitised:
        dsn_raw  = raw[25:69]
        vol_raw  = raw[74:80]
        dsn_hex  = dsn_raw.hex()
        vol_hex  = vol_raw.hex()
        dsn_valid = all(b in VALID_DSN_EBCDIC for b in dsn_raw)
        hex_lines.append(
            f"Record {rec_num}: DSN hex={dsn_hex}  VOL hex={vol_hex}  "
            f"DSN_bytes_valid={'YES' if dsn_valid else 'NO — contains non-DSN EBCDIC bytes'}"
        )

# Write hex diagnostic file
pathlib.Path(hexout).write_text('\n'.join(hex_lines) + '\n')
print(f"\n[Hex diagnostic written to {hexout}]", file=sys.stderr)
PYEOF
}

# upload ASM source
echo "=== Uploading HLASM probe '$PROBE_NAME' as member '$MEMBER' ==="
echo "=== Output dataset  : '$OUTPUT_DSN' ==="
echo "=== Listing dataset : '$LISTING_DSN' ==="

MAX_UPLOAD_ATTEMPTS=3
UPLOAD_OK=0
for upload_attempt in $(seq 1 $MAX_UPLOAD_ATTEMPTS); do
  echo "Upload attempt $upload_attempt / $MAX_UPLOAD_ATTEMPTS..."
  [ "$upload_attempt" -gt 1 ] && sleep 3
  UPLOAD_RESPONSE=$(ftp -inv "$HOST" 2>&1 <<FTPEOF
user $USER $PASS
quote TYPE A
put $PROBE_LOCAL "'$ASM_PDS($MEMBER)'"
bye
FTPEOF
)
  echo "$UPLOAD_RESPONSE"
  if upload_succeeded "$UPLOAD_RESPONSE"; then
    UPLOAD_OK=1
    break
  fi
  echo "Upload attempt $upload_attempt failed, retrying..."
done

if [ "$UPLOAD_OK" -ne 1 ]; then
  echo "ERROR: ASM upload failed after $MAX_UPLOAD_ATTEMPTS attempts."
  exit 1
fi

# submit JCL
echo "=== Submitting JCL ==="
sleep 1
SUBMIT_RESPONSE=$(ftp -inv "$HOST" 2>&1 <<FTPEOF
user $USER $PASS
quote TYPE A
quote site filetype=jes
put "$TMP_JCL_SUBST"
bye
FTPEOF
)
echo "$SUBMIT_RESPONSE"

JOBID=$(echo "$SUBMIT_RESPONSE" \
  | grep -i "known to JES as" \
  | grep -oE 'JOB[0-9]+' \
  | head -1)

if [ -z "$JOBID" ]; then
  echo "ERROR: Could not extract JobID."
  exit 1
fi
echo "JobID = $JOBID"

# Poll for ASM listing (ASCII fine here — pure printer text, no raw storage bytes)
echo "=== Polling for ASM listing '$LISTING_DSN' ==="
MAX_ATTEMPTS=20
SLEEP=5

for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  echo "Listing attempt $attempt / $MAX_ATTEMPTS..."
  rm -f "$LOCAL_LISTING"
  ftp_get_ascii "$LISTING_DSN" "$LOCAL_LISTING" | grep -Ev "^(user|quote|bye|ftp>)" | tail -3

  if [ -f "$LOCAL_LISTING" ] && [ -s "$LOCAL_LISTING" ]; then
    echo "=== ASM listing saved to $LOCAL_LISTING ==="
    cat "$LOCAL_LISTING"
    echo "============================================"
    ftp_delete_dataset "$LISTING_DSN"

    HLASM_RC=$(grep -m1 'Return Code' "$LOCAL_LISTING" 2>/dev/null \
               | awk '{print $NF + 0}')
    if [ "${HLASM_RC:-0}" -gt 4 ]; then
      echo "ERROR: Assembly failed with Return Code ${HLASM_RC} — see listing above."
      exit 1
    fi
    break
  fi

  echo "Not ready, sleeping ${SLEEP}s..."
  sleep "$SLEEP"
done

if [ ! -s "$LOCAL_LISTING" ]; then
  echo "WARNING: ASM listing '$LISTING_DSN' never appeared after $((MAX_ATTEMPTS * SLEEP))s."
fi

# Poll for program output — binary transfer, decoded client-side
echo "=== Polling for output dataset '$OUTPUT_DSN' ==="

OUTPUT_READY=0
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  echo "Attempt $attempt / $MAX_ATTEMPTS..."
  rm -f "$LOCAL_OUTPUT_BIN"

  ftp_get_binary "$OUTPUT_DSN" "$LOCAL_OUTPUT_BIN" \
    | grep -Ev "^(user|quote|bye|ftp>)" | tail -3

  if [ -f "$LOCAL_OUTPUT_BIN" ] && [ -s "$LOCAL_OUTPUT_BIN" ]; then
    echo "=== Binary output saved to $LOCAL_OUTPUT_BIN ==="
    ftp_delete_dataset "$OUTPUT_DSN"
    OUTPUT_READY=1
    break
  fi

  echo "Not ready, sleeping ${SLEEP}s..."
  sleep "$SLEEP"
done

if [ "$OUTPUT_READY" -ne 1 ]; then
  echo "ERROR: Timed out after $((MAX_ATTEMPTS * SLEEP))s — '$OUTPUT_DSN' never appeared."
  echo "       Check listing above for assembly/link errors."
  exit 1
fi

echo "=== Probe output ==="
decode_ebcdic_output "$LOCAL_OUTPUT_BIN" "$LOCAL_OUTPUT_HEX" 133 | tee "$LOCAL_OUTPUT"

echo ""
echo "=== Hex diagnostic (raw EBCDIC bytes per field) ==="
cat "$LOCAL_OUTPUT_HEX"
echo ""
echo "If DSN bytes are marked 'NO', CVTAPF is not pointing to a standard"
echo "APF table. Check SYS1.PARMLIB(IEAAPFxx) and CVTAPF value in storage."
echo "=== Done ==="