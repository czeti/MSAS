#!/usr/bin/bash

set -e

HOST="${MF_HOST:-192.168.8.210}"
USER="${MF_USER:-IBMUSER}"
PASS="${MF_PASS:-SYS1}"
REXX_PDS="${REXX_PDS:-IBMUSER.PROBES.REXX}"
OUTPUT_DSN_BASE="${OUTPUT_DSN:-IBMUSER.MSAS.OUTPUT}"
LOCAL_OUTPUT="${LOCAL_OUTPUT:-/tmp/test_output/test_output.txt}"

PROBE_NAME=${1:-racf_checks}
MEMBER=$(echo "$PROBE_NAME" \
 | tr '[:lower:]' '[:upper:]' \
 | tr -d '_-' \
 | cut -c1-8)   #conform to mvs spec

PID_SUFFIX=$(printf '%05d' $(($$ % 99999))) #keep pid < 99999
OUTPUT_DSN="${OUTPUT_DSN_BASE}.${MEMBER}.P${PID_SUFFIX}" # construct data set name 

PROBE_LOCAL=probes/rexx/${PROBE_NAME}.rex
JCL_TEMPLATE=probes/jcl/RUN_REXX.jcl
OUTPUT_DIR=$(dirname "$LOCAL_OUTPUT")
TMP_JCL=/tmp/run_rexx_$$.jcl
TMP_JCL_SUBST=/tmp/run_rexx_subst_$$.jcl

mkdir -p "$OUTPUT_DIR"
trap "rm -f $TMP_JCL $TMP_JCL_SUBST" EXIT   #ensure cleanup

cp "$JCL_TEMPLATE" "$TMP_JCL"

sed -e "s/%MEMBER%/${MEMBER}/g" -e "s/%OUTPUT_DSN%/${OUTPUT_DSN}/g" "$TMP_JCL" > "$TMP_JCL_SUBST"

upload_succeeded() {
  echo "$1" | grep -qi "Transfer completed"
}

ftp_failed() {
  echo "$1" | grep -qiE "^[45][0-9][0-9]|not found|failed|error|cannot|invalid|rejected|not connected|unable to obtain|exclusive use"
}

echo "=== UPLOAD REX PROBE: $PROBE_NAME as MEMBER: $MEMBER ==="
echo "=== Output dataset would be $OUTPUT_DSN ==="

MAX_UPLOAD_ATTEMPTS=3
for upload_attempt in $(seq 1 $MAX_UPLOAD_ATTEMPTS); do
    echo "Upload attempt: $upload_attempt / $MAX_UPLOAD_ATTEMPTS" 

    [ "$upload_attempt" -gt 1 ] && sleep 3 # sleep to let daemon recover

    UPLOAD_RESPONSE=$(ftp -inv "$HOST" 2>&1 <<FTPEOF
user $USER $PASS
quote TYPE A
put $PROBE_LOCAL "'$REXX_PDS($MEMBER)'"
bye
FTPEOF
)
    echo "$UPLOAD_RESPONSE"

    if upload_succeeded "$UPLOAD_RESPONSE"; then
      break
    fi     
    echo "Upload attempt failed, retrying..." 
done

echo "=== SUBMITTING JCL ==="
sleep 1

SUBMIT_RESPONSE=$(ftp -inv "$HOST" 2>&1 << FTPEOF
    user $USER $PASS
    quote TYPE A
    quote site filetype=jes
    put $TMP_JCL_SUBST
    bye
FTPEOF
)

echo "$SUBMIT_RESPONSE"

JOB_ID=$(echo "$SUBMIT_RESPONSE" \
 | grep -i "known to JES as" \
 | grep -oE "JOB[0-9]+" \
 | head -1 )

if [ -z "$JOB_ID" ]; then
  echo "Failed to extract job ID. JCL likely rejected. Recheck job card"
fi
echo "JOB ID = $JOB_ID"

echo "=== Retrieving $OUTPUT_DSN ===="
MAX_ATTEMPTS=10
SLEEP=5

for attempt in $(seq 1 $MAX_ATTEMPTS); do
  echo "Retrieval attempt: $attempt / $MAX_ATTEMPTS"
  rm -rf "$LOCAL_OUTPUT"

  [ "$attempt" -gt 1 ] && sleep $SLEEP

  POLL_RESPONSE=$(ftp -inv "$HOST" 2>&1 <<FTPEOF || true
    user $USER $PASS
    quote TYPE A
    get "'$OUTPUT_DSN'" "$LOCAL_OUTPUT"
    bye
FTPEOF
)

  echo "=== POLL RESPONSE ==="
  echo "$POLL_RESPONSE" \
   | grep -Ev "^(user|quote|bye|ftp>)" \
   | tail -5

  if [ -f "$LOCAL_OUTPUT" ] && [ -s "$LOCAL_OUTPUT" ]; then
    ftp -inv "$HOST" 2>&1 <<DELEOF || true
    user $USER $PASS
    quote site filetype=seq
    delete "'$OUTPUT_DSN'"
    bye
DELEOF
    break
  fi
done