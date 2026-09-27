#!/bin/bash
# Fingerprint Enrollment Verification Test Suite
# Back-to-front: verifies enrollment behavior via logcat analysis
# Usage: ./verify_enrollment.sh [device_serial]
#
# Run AFTER attempting enrollment. Parses logcat for bauth_* tags
# and checks each critical condition that must be met for enrollment to succeed.

SERIAL="${1:-${ANDROID_SERIAL:?set ANDROID_SERIAL or pass the device serial}}"
ADB="adb -s $SERIAL"
PASS=0
FAIL=0
WARN=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }

# Capture bauth logs
LOGFILE="/tmp/enrollment_verify_$(date +%s).log"
$ADB shell "logcat -d -s bauth_FPBAuthService:* bauth_TLC_Communicator:* bauth_FPEGOPTBAuthSensorControl:* bauth_FPBAuthServiceStorage:*" > "$LOGFILE" 2>/dev/null

if [ ! -s "$LOGFILE" ]; then
    echo "ERROR: No logcat data captured. Is device connected?"
    exit 1
fi

echo "=========================================="
echo " Fingerprint Enrollment Verification"
echo "=========================================="
echo "Log: $LOGFILE ($(wc -l < "$LOGFILE") lines)"
echo ""

# ---- TEST 1: Enrollment was initiated ----
echo "--- Enrollment Initiation ---"
ENROLL_COUNT=$(grep -c 'FPBAuthService, 8602' "$LOGFILE")
if [ "$ENROLL_COUNT" -gt 0 ]; then
    pass "Enrollment initiated ($ENROLL_COUNT time(s))"
else
    fail "No enrollment initiated (missing FPBAuthService 8602)"
fi

# ---- TEST 2: set_enroll_session called ----
SESSION_FLAG=$(grep -c 'set_enroll_session : gSession_Flag' "$LOGFILE")
if [ "$SESSION_FLAG" -gt 0 ]; then
    pass "Enrollment session opened (gSession_Flag set)"
else
    fail "Enrollment session not opened"
fi

# ---- TEST 3: persbds behavior ----
echo ""
echo "--- BDS Data Preservation (CRITICAL) ---"
PERSBDS=$(grep -c 'persbds' "$LOGFILE")
if [ "$PERSBDS" -gt 0 ]; then
    warn "persbds was called ($PERSBDS time(s)) — BDS data may be at risk"

    # Check if BDS was loaded with data
    LBL_VALUES=$(grep 'lbl' "$LOGFILE" | grep -oP 'lbl \K[0-9]+')
    for lbl in $LBL_VALUES; do
        if [ "$lbl" -eq 0 ]; then
            fail "BDS loaded with 0 bytes (lbl 0) — TEE has empty calibration!"
        else
            pass "BDS loaded with $lbl bytes — calibration data preserved!"
        fi
    done
else
    pass "persbds not called — BDS data preserved (templates exist)"
fi

# ---- TEST 4: pre_wce and wce values ----
echo ""
echo "--- WCE (Window Capture Enrollment) Mode ---"
PRE_WCE=$(grep 'pre_wce' "$LOGFILE" | tail -1 | grep -oP 'pre_wce \K[-0-9]+')
# Match "wce X Y" but NOT "post_wce" or "pre_wce"
WCE_LINE=$(grep -P 'wce \d+ \d+' "$LOGFILE" | grep -v 'pre_wce\|post_wce' | tail -1)
WCE_VAL=$(echo "$WCE_LINE" | grep -oP '(?<!pre_|post_)wce \K[0-9]+')

if [ -n "$PRE_WCE" ]; then
    if [ "$PRE_WCE" -gt 0 ] 2>/dev/null; then
        pass "pre_wce is positive: $PRE_WCE (healthy)"
    else
        fail "pre_wce is negative/zero: $PRE_WCE (degraded calibration)"
    fi
fi

if [ -n "$WCE_VAL" ]; then
    if [ "$WCE_VAL" -ge 7 ]; then
        pass "wce = $WCE_VAL (optimal quality threshold)"
    elif [ "$WCE_VAL" -ge 5 ]; then
        fail "wce = $WCE_VAL (degraded — need >= 7 for reliable enrollment)"
    else
        fail "wce = $WCE_VAL (severely degraded)"
    fi
    echo "  Full wce line: $WCE_LINE"
else
    fail "No wce value found in logs"
fi

# ---- TEST 5: Sensor status ----
echo ""
echo "--- Sensor Status ---"
SENSOR_STATUS=$(grep 'check_opcode.*opcode = 5.*func_ret_val = 0' "$LOGFILE" | head -1)
if [ -n "$SENSOR_STATUS" ]; then
    pass "Sensor reporting data (opcode 5 OK)"
else
    warn "No sensor data events found"
fi

# ---- TEST 6: CBGE calibration ----
CBGE=$(grep -c 'cOp : 43' "$LOGFILE")
POSTINIT=$(grep -c 'cOp : 16' "$LOGFILE")
if [ "$CBGE" -gt 0 ]; then
    pass "CBGE calibration ran ($CBGE time(s))"
else
    fail "No CBGE calibration (cOp:43) found"
fi
if [ "$POSTINIT" -gt 0 ]; then
    pass "Post-init calibration ran ($POSTINIT time(s))"
else
    warn "No post-init calibration (cOp:16) found"
fi

# ---- TEST 7: Cell ID loading ----
echo ""
echo "--- Cell ID ---"
CID_LF=$(grep -c 'cid lf' "$LOGFILE")
CIDLEN=$(grep 'cidlen' "$LOGFILE" | tail -1 | grep -oP 'cidlen : \K[0-9]+')
VCIDC=$(grep -c 'vcidc' "$LOGFILE")
if [ "$CID_LF" -gt 0 ] && [ "${CIDLEN:-0}" -gt 0 ]; then
    pass "Cell ID loaded ($CID_LF times, length=$CIDLEN, verified=$VCIDC times)"
else
    fail "Cell ID not loaded properly (cid_lf=$CID_LF, cidlen=${CIDLEN:-0})"
fi

# ---- TEST 8: Capture results ----
echo ""
echo "--- Capture Results ---"
GOOD_CAPTURES=$(grep -c 'fpop : 100024' "$LOGFILE")
BAD_CAPTURES=$(grep -c 'fpop : 100025' "$LOGFILE")
TOTAL=$((GOOD_CAPTURES + BAD_CAPTURES))
if [ "$TOTAL" -gt 0 ]; then
    SUCCESS_RATE=$((GOOD_CAPTURES * 100 / TOTAL))
    echo "  Good captures:  $GOOD_CAPTURES"
    echo "  Bad captures:   $BAD_CAPTURES"
    echo "  Total attempts: $TOTAL"
    echo "  Success rate:   ${SUCCESS_RATE}%"

    if [ "$SUCCESS_RATE" -ge 50 ]; then
        pass "Capture success rate ${SUCCESS_RATE}% (>= 50% threshold)"
    elif [ "$SUCCESS_RATE" -ge 20 ]; then
        warn "Capture success rate ${SUCCESS_RATE}% (marginal)"
    else
        fail "Capture success rate ${SUCCESS_RATE}% (too low for enrollment completion)"
    fi
else
    warn "No capture attempts found"
fi

# ---- TEST 9: Quality check pattern ----
echo ""
echo "--- Quality Check Pattern ---"
QUALITY_PASS=$(grep 'opcode = 6, func_ret_val = 0' "$LOGFILE" | wc -l)
QUALITY_SKIP=$(grep 'return value from qsapp is wrong : 39' "$LOGFILE" | wc -l)
echo "  Quality passes (opcode 6): $QUALITY_PASS"
echo "  Quality failures (ret=39):  $QUALITY_SKIP"

# Check if failures are clustered (all after a certain point)
if [ "$GOOD_CAPTURES" -gt 0 ] && [ "$BAD_CAPTURES" -gt 0 ]; then
    # Get timestamps of last good and first bad capture
    LAST_GOOD_TIME=$(grep 'fpop : 100024' "$LOGFILE" | tail -1 | awk '{print $2}')
    FIRST_BAD_TIME=$(grep 'fpop : 100025' "$LOGFILE" | head -1 | awk '{print $2}')

    # Check if any good captures happen AFTER the first bad one
    GOOD_AFTER_BAD=$(grep 'fpop : 100024' "$LOGFILE" | awk -v bad="$FIRST_BAD_TIME" '$2 > bad' | wc -l)

    if [ "$GOOD_AFTER_BAD" -eq 0 ] && [ "$BAD_CAPTURES" -gt 5 ]; then
        fail "All failures clustered after captures stopped — hard cutoff pattern (wce exhaustion)"
    elif [ "$GOOD_AFTER_BAD" -gt 0 ]; then
        pass "Captures recovered after failures ($GOOD_AFTER_BAD good after first bad)"
    fi
fi

# ---- TEST 10: Enrollment completion ----
echo ""
echo "--- Enrollment Completion ---"
ENROLL_COMPLETE=$(grep -c 'fpop : 100001' "$LOGFILE")
if [ "$ENROLL_COMPLETE" -gt 0 ]; then
    pass "ENROLLMENT COMPLETED SUCCESSFULLY (fpop 100001)"
else
    fail "Enrollment did NOT complete (no fpop 100001)"
fi

# ---- TEST 11: Touch events ----
echo ""
echo "--- Touch Event Handling ---"
TOUCH_DOWN=$(grep 'tfd 2.*2$' "$LOGFILE" | wc -l)
TOUCH_UP=$(grep 'tfd 1 1 1' "$LOGFILE" | wc -l)
if [ "$TOUCH_DOWN" -gt 0 ] && [ "$TOUCH_UP" -gt 0 ]; then
    pass "Touch events delivered (down=$TOUCH_DOWN, up=$TOUCH_UP)"
else
    warn "Touch events may be missing (down=$TOUCH_DOWN, up=$TOUCH_UP)"
fi

# ---- TEST 12: SensorControl sequence ----
echo ""
echo "--- Sensor Control ---"
SC_178=$(grep -c 'SensorControl, 178' "$LOGFILE")
SC_200=$(grep -c 'SensorControl, 200' "$LOGFILE")
SC_242=$(grep -c 'SensorControl, 242' "$LOGFILE")
SC_448=$(grep -c 'SensorControl, 448' "$LOGFILE")
SC_603=$(grep -c 'SensorControl, 603' "$LOGFILE")
echo "  SensorControl 178 (init):       $SC_178"
echo "  SensorControl 200 (ready):      $SC_200"
echo "  SensorControl 242 (capture):    $SC_242"
echo "  SensorControl 448 (post-calib): $SC_448"
echo "  SensorControl 603 (enroll):     $SC_603"

# ---- TEST 12b: optHbmInterrupt calls ----
echo ""
echo "--- HBM Sensor Synchronization ---"
HBM_FILE="/tmp/enrollment_verify_hal_$(date +%s).log"
$ADB shell "logcat -d -s android.hardware.biometrics.fingerprint-service.samsung:*" > "$HBM_FILE" 2>/dev/null
HBM_ON=$(grep -c 'optHbmInterrupt(1)' "$HBM_FILE")
HBM_OFF=$(grep -c 'optHbmInterrupt(0)' "$HBM_FILE")
HBM_ABORT=$(grep -c 'optHbmInterrupt(2)' "$HBM_FILE")
HBM_UNAVAIL=$(grep -c 'optHbmInterrupt unavailable' "$HBM_FILE")
if [ "$HBM_UNAVAIL" -gt 0 ]; then
    fail "optHbmInterrupt unavailable — FPBAuthService singleton not resolved!"
elif [ "$HBM_ON" -gt 0 ]; then
    pass "optHbmInterrupt called: on=$HBM_ON off=$HBM_OFF abort=$HBM_ABORT"
else
    warn "No optHbmInterrupt calls found (no finger touches yet?)"
fi

DISPLAY_STATUS=$(grep -c 'set_display_status' "$HBM_FILE")
if [ "$DISPLAY_STATUS" -gt 0 ]; then
    pass "set_display_status called ($DISPLAY_STATUS times)"
else
    warn "No set_display_status calls found"
fi

BAUTH_RESOLVED=$(grep -c 'Resolved FPBAuthService' "$HBM_FILE")
if [ "$BAUTH_RESOLVED" -gt 0 ]; then
    pass "FPBAuthService singleton resolved"
else
    fail "FPBAuthService singleton NOT resolved — direct methods unavailable"
fi
rm -f "$HBM_FILE"

# ---- TEST 13: BDS update ----
echo ""
echo "--- BDS Update ---"
BDS_UPDATE=$(grep 'done l:' "$LOGFILE" | tail -1)
if [ -n "$BDS_UPDATE" ]; then
    BDS_SIZE=$(echo "$BDS_UPDATE" | grep -oP 'l:\K[0-9]+')
    BDS_RET=$(echo "$BDS_UPDATE" | grep -oP 'r:\K[-0-9]+')
    if [ "${BDS_RET:-1}" -eq 0 ]; then
        pass "BDS update OK (size=$BDS_SIZE, ret=$BDS_RET)"
    else
        warn "BDS update may have failed (size=$BDS_SIZE, ret=$BDS_RET)"
    fi
else
    warn "No BDS update found"
fi

# ---- TEST 14: immutable flag check ----
echo ""
echo "--- File Protection ---"
LSATTR=$($ADB shell "lsattr /data/vendor/biometrics/meta/egoptbds.dat 2>/dev/null" | head -1)
if echo "$LSATTR" | grep -q 'i'; then
    pass "egoptbds.dat has immutable flag set (protected from persbds deletion)"
else
    warn "egoptbds.dat is NOT immutable (vulnerable to persbds deletion)"
fi

# ---- SUMMARY ----
echo ""
echo "=========================================="
echo " RESULTS: $PASS passed, $FAIL failed, $WARN warnings"
echo "=========================================="

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}All critical tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$FAIL critical test(s) failed.${NC}"
    echo ""
    echo "Key indicators:"
    echo "  wce value:       ${WCE_VAL:-unknown} (need >= 7)"
    echo "  lbl value:       ${LBL_VALUES:-unknown} (need > 0)"
    echo "  Success rate:    ${SUCCESS_RATE:-0}%"
    echo "  Completed:       $([ "$ENROLL_COMPLETE" -gt 0 ] && echo YES || echo NO)"
    exit 1
fi
