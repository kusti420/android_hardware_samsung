#!/bin/bash
# Build-time verification for Samsung UDFPS fingerprint HAL.
# Run before deploying to catch known failure patterns at build time.
#
# Exit codes:
#   0 — all checks pass
#   1 — critical failure (will crash or fail enrollment)
#   2 — warning (may work but suboptimal)
#
# Usage:
#   ./verify_build.sh [--kernel-dir DIR] [--hal-dir DIR] [--device-dir DIR]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HAL_DIR="${SCRIPT_DIR}/.."
KERNEL_DIR="${KERNEL_DIR:-$HOME/git/android/kernel/samsung/sm7325}"
DEVICE_DIR="${DEVICE_DIR:-$HOME/git/android/device/samsung/sm7325-common}"

PASS=0
FAIL=0
WARN=0

pass() { PASS=$((PASS + 1)); printf "  \033[32m✓\033[0m %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31m✗\033[0m %s\n" "$1"; }
warn() { WARN=$((WARN + 1)); printf "  \033[33m!\033[0m %s\n" "$1"; }

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel-dir) KERNEL_DIR="$2"; shift 2;;
        --hal-dir) HAL_DIR="$2"; shift 2;;
        --device-dir) DEVICE_DIR="$2"; shift 2;;
        *) shift;;
    esac
done

echo ""
echo "=== Samsung UDFPS HAL Build Verification ==="
echo ""

# ─── 1. Kernel: type_check capping ───────────────────────────────────
echo "── Kernel (type_check sysfs) ──"

FP_COMMON="$KERNEL_DIR/drivers/fingerprint/fingerprint_common.c"
if [[ -f "$FP_COMMON" ]]; then
    if grep -q "BUILD_CHECK:TYPE_CHECK_CAP" "$FP_COMMON"; then
        pass "type_check capped to SENSOR_OK in set_sensor_type()"
    else
        fail "type_check NOT capped — BAuth will trigger persbds and wipe calibration"
        echo "       Fix: in set_sensor_type(), cap positive values to SENSOR_OK (1)"
    fi
else
    warn "fingerprint_common.c not found at $FP_COMMON — cannot verify"
fi

# sde_crtc must NOT pre-set finger_mask — it blocks the first real HBM write
SDE_CRTC="$KERNEL_DIR/techpack/display/msm/sde/sde_crtc.c"
if [[ -f "$SDE_CRTC" ]]; then
    if grep -v '^\s*//' "$SDE_CRTC" | grep -v '^\s*\*' | grep -q 'finger_mask_bl_level = 331'; then
        fail "sde_crtc.c pre-sets finger_mask_bl_level=331 — blocks first HBM write (mask already enabled)"
        echo "       Fix: remove the finger_mask hack from _sde_crtc_check_zpos"
    elif grep -v '^\s*//' "$SDE_CRTC" | grep -v '^\s*\*' | grep -q 'finger_mask = 1'; then
        fail "sde_crtc.c pre-sets finger_mask=1 — blocks first HBM write"
    else
        pass "sde_crtc.c does NOT pre-set finger_mask — HAL controls HBM"
    fi
else
    warn "sde_crtc.c not found at $SDE_CRTC"
fi

FP_HEADER="$KERNEL_DIR/drivers/fingerprint/fingerprint.h"
if [[ -f "$FP_HEADER" ]]; then
    SENSOR_OK_VAL=$(grep -oP 'SENSOR_OK\s*[=,]?\s*' "$FP_HEADER" | head -1)
    if [[ -n "$SENSOR_OK_VAL" ]]; then
        pass "SENSOR_OK defined in fingerprint.h"
    else
        fail "SENSOR_OK not found in fingerprint.h — enum may be broken"
    fi
else
    warn "fingerprint.h not found"
fi

# ─── 2. HAL: HBM synchronization ────────────────────────────────────
echo ""
echo "── HAL (HBM sync in Session.cpp) ──"

SESSION_CPP="$HAL_DIR/Session.cpp"
if [[ -f "$SESSION_CPP" ]]; then
    # optHbmInterrupt calls ARE REQUIRED — BAuth needs HBM state for dual capture
    if grep -v '^\s*//' "$SESSION_CPP" | grep -q 'callOptHbmInterrupt(1)'; then
        pass "callOptHbmInterrupt(1) in onPointerDown — BAuth knows HBM on"
    else
        fail "missing callOptHbmInterrupt(1) — BAuth blind to HBM → error 39"
    fi

    # setDisplayStatus also needed
    if grep -v '^\s*//' "$SESSION_CPP" | grep -q 'callSetDisplayStatus'; then
        pass "callSetDisplayStatus calls present"
    else
        warn "missing callSetDisplayStatus — BAuth may not track display state"
    fi

    # callSessionClose must NOT be in Session::close
    CLOSE_FUNC=$(sed -n '/Session::close()/,/^}/p' "$SESSION_CPP" 2>/dev/null)
    if echo "$CLOSE_FUNC" | grep -v '^\s*//' | grep -q 'callSessionClose'; then
        fail "callSessionClose in Session::close — invalidates HAT (error 61)"
    else
        pass "no callSessionClose in close() — HAT challenge preserved"
    fi

    # HBM abort on error path
    if grep -q 'setHBM(false)' "$SESSION_CPP"; then
        pass "setHBM(false) in error/cancel paths"
    else
        warn "missing HBM-off in error paths — screen may stay bright"
    fi

    # Enrollment delay — brief settle, not blocking 4s wait
    if grep -q 'sleep_for.*500ms' "$SESSION_CPP"; then
        pass "500ms CBGE settle delay (reduced from 4s)"
    elif grep -q 'sleep_for.*3s' "$SESSION_CPP"; then
        warn "still using old 3s CBGE delay — should be 500ms with working optHbmInterrupt"
    else
        warn "no CBGE settling delay found"
    fi

    # mask_brightness error logging
    if grep -q 'mask_brightness.*strerror\|mask_brightness.*errno\|mask_brightness write' "$SESSION_CPP"; then
        pass "mask_brightness writes have error logging"
    else
        warn "mask_brightness writes lack error logging — silent failures"
    fi

    # User directory creation — must mkdir fp/User_%d before set_active_group
    if grep -q 'mkdir(filename' "$SESSION_CPP" || grep -q 'mkdir.*FINGERPRINT_DATA_DIR' "$SESSION_CPP"; then
        pass "Session creates fp/User_%d directory before set_active_group"
    else
        fail "Session missing mkdir for fp/User_%d — enrollment templates can't be saved"
        echo "       BAuth writes templates to fp/User_%d/%d_Ntmpl.dat; directory must exist"
    fi

    # sys/stat.h for mkdir
    if grep -q '#include <sys/stat.h>' "$SESSION_CPP"; then
        pass "sys/stat.h included for mkdir"
    else
        fail "sys/stat.h missing — mkdir won't compile"
    fi

    # actual_mask_brightness polling — setHBM must wait for confirmation
    if grep -q 'actual_mask_brightness' "$SESSION_CPP"; then
        pass "setHBM polls actual_mask_brightness — waits for HBM to engage"
    else
        fail "setHBM missing actual_mask_brightness poll — BAuth may capture before HBM on"
    fi

    # onPointerDown ordering: setHBM BEFORE optHbmInterrupt
    # HBM must physically engage before telling BAuth it's on
    POINTER_DOWN=$(sed -n '/onPointerDown/,/^}/p' "$SESSION_CPP" 2>/dev/null)
    HBM_LINE=$(echo "$POINTER_DOWN" | grep -n 'setHBM(true)' | head -1 | cut -d: -f1)
    OPT_LINE=$(echo "$POINTER_DOWN" | grep -n 'callOptHbmInterrupt(1)' | head -1 | cut -d: -f1)
    if [[ -n "$HBM_LINE" && -n "$OPT_LINE" && "$HBM_LINE" -lt "$OPT_LINE" ]]; then
        pass "onPointerDown: setHBM before optHbmInterrupt (HBM ready before BAuth)"
    elif [[ -n "$HBM_LINE" && -n "$OPT_LINE" ]]; then
        fail "onPointerDown: optHbmInterrupt before setHBM — BAuth thinks HBM on before it is"
    else
        warn "could not verify onPointerDown ordering"
    fi
else
    fail "Session.cpp not found at $SESSION_CPP"
fi

# ─── 3. HAL: pointer resolution strategy ─────────────────────────────
echo ""
echo "── HAL (FPBAuthService pointer chain) ──"

LEGACY_CPP="$HAL_DIR/LegacyHAL.cpp"
LEGACY_H="$HAL_DIR/LegacyHAL.h"
if [[ -f "$LEGACY_CPP" && -f "$LEGACY_H" ]]; then
    # Must use fresh resolution, NOT cached pointer
    if grep -q 'resolveFPBAuthService' "$LEGACY_CPP"; then
        pass "resolveFPBAuthService() — fresh pointer resolution each call"
    else
        fail "missing resolveFPBAuthService — cached pointer goes stale → SIGSEGV"
    fi

    # Must store BSS address, not value
    if grep -q 'mGFPBAuthServiceAddr' "$LEGACY_H"; then
        pass "stores gFPBAuthService BSS address (stable)"
    else
        fail "caching FPBAuthService value — stale after BAuth recreates it"
    fi

    # Must NOT have a +0x18 intermediate dereference.
    # gFPBAuthService holds FPBAuthService* directly (33MB scudo:secondary).
    if grep -q 'reinterpret_cast.*+ 0x18' "$LEGACY_CPP"; then
        fail "+0x18 dereference present — gFPBAuthService is FPBAuthService* directly, no indirection"
    else
        pass "no +0x18 dereference — direct FPBAuthService* from global"
    fi

    # optHbmInterrupt symbol resolution
    if grep -q 'optHbmInterruptEj' "$LEGACY_CPP"; then
        pass "optHbmInterrupt symbol mangled name correct"
    else
        fail "wrong/missing optHbmInterrupt mangled symbol"
    fi

    # Diagnostic logging at resolution time
    if grep -q 'gFPBAuthService BSS addr' "$LEGACY_CPP"; then
        pass "pointer resolution has diagnostic logging"
    else
        warn "missing diagnostic logging — hard to debug pointer issues"
    fi

    # mask_brightness init reset — must clear stale finger_mask from boot
    if grep -q 'mask_brightness.*reset\|mask_brightness.*clear\|mask_brightness.*"0"' "$LEGACY_CPP"; then
        pass "mask_brightness reset in openHal — clears stale boot state"
    else
        fail "no mask_brightness init reset — first HBM write will be no-op if kernel pre-set"
    fi

    # Base biometrics directory creation in openHal
    if grep -q 'kBioDirs\|biometrics/fp\|mkdir.*biometrics' "$LEGACY_CPP"; then
        pass "openHal creates base biometrics directories"
    else
        fail "openHal missing biometrics directory creation — BAuth mkdir fails silently"
    fi
else
    fail "LegacyHAL.cpp or .h not found"
fi

# ─── 4. init.rc: chattr consistency ─────────────────────────────────
echo ""
echo "── init.rc (BDS protection) ──"

INIT_RC="$DEVICE_DIR/init/init.fingerprint.rc"
if [[ -f "$INIT_RC" ]]; then
    HAS_CHATTR=$(grep -c 'chattr.*egoptbds' "$INIT_RC" 2>/dev/null || true)
    HAS_TYPE_CAP=$(grep -q "BUILD_CHECK:TYPE_CHECK_CAP" "$FP_COMMON" 2>/dev/null && echo "yes" || echo "no")

    if [[ "$HAS_TYPE_CAP" == "yes" && "$HAS_CHATTR" -gt 0 ]]; then
        warn "chattr +i on egoptbds.dat still in init.rc but type_check already capped"
        echo "       chattr blocks BDS writes during enrollment — remove it"
    elif [[ "$HAS_TYPE_CAP" != "yes" && "$HAS_CHATTR" -eq 0 ]]; then
        fail "type_check NOT capped AND no chattr +i — persbds WILL delete BDS"
        echo "       Fix: either cap type_check in kernel OR add chattr +i to init.rc"
    elif [[ "$HAS_TYPE_CAP" == "yes" && "$HAS_CHATTR" -eq 0 ]]; then
        pass "type_check capped, no chattr +i — BDS writable during enrollment"
    else
        pass "chattr +i protects BDS (workaround — prefer kernel type_check fix)"
    fi
else
    warn "init.fingerprint.rc not found"
fi

# ─── 5. Binary: libbauthserver.so symbols ────────────────────────────
echo ""
echo "── Binary (libbauthserver.so) ──"

# Try to find the prebuilt or built binary
BAUTH_SO=""
for candidate in \
    "$HOME/git/android/out/target/product/a52sxq/vendor/lib64/libbauthserver.so" \
    "$HOME/git/android/vendor/samsung/sm7325-common/proprietary/vendor/lib64/libbauthserver.so" \
    "$HOME/git/android/vendor/samsung/a52sxq/proprietary/vendor/lib64/libbauthserver.so"; do
    if [[ -f "$candidate" ]]; then
        BAUTH_SO="$candidate"
        break
    fi
done

if [[ -n "$BAUTH_SO" ]]; then
    SYMTMP=$(mktemp)
    trap "rm -f $SYMTMP" EXIT
    readelf --dyn-syms -W "$BAUTH_SO" > "$SYMTMP" 2>/dev/null || \
        nm -D "$BAUTH_SO" > "$SYMTMP" 2>/dev/null || true

    if [[ ! -s "$SYMTMP" ]]; then
        warn "cannot read symbol table from $BAUTH_SO"
    else
        # Core HAL API symbols
        REQUIRED_SYMBOLS=(
            "ss_fingerprint_open"
            "ss_fingerprint_close"
            "ss_set_notify_callback"
            "ss_fingerprint_pre_enroll"
            "ss_fingerprint_enroll"
            "ss_fingerprint_post_enroll"
            "ss_fingerprint_authenticate"
            "ss_fingerprint_cancel"
            "ss_fingerprint_remove"
            "ss_fingerprint_enumerate"
            "ss_fingerprint_set_active_group"
            "ss_fingerprint_get_auth_id"
            "ss_fingerprint_request"
        )

        for sym in "${REQUIRED_SYMBOLS[@]}"; do
            if grep -q "$sym" "$SYMTMP"; then
                pass "symbol: $sym"
            else
                fail "missing symbol: $sym — HAL will fail to load"
            fi
        done

        # FPBAuthService direct method symbols
        echo ""
        echo "── Binary (BAuth direct method symbols) ──"

        if grep -q "gFPBAuthService" "$SYMTMP"; then
            pass "gFPBAuthService singleton pointer"
        else
            fail "gFPBAuthService missing — cannot resolve BAuth methods"
        fi

        if grep -q "optHbmInterruptEj" "$SYMTMP"; then
            pass "FPBAuthService::optHbmInterrupt(uint) symbol"
        else
            fail "optHbmInterrupt missing — cannot control HBM for dual capture"
        fi

        if grep -q "set_display_statusEi" "$SYMTMP"; then
            pass "FPBAuthService::set_display_status(int) symbol"
        else
            warn "set_display_status missing — display state tracking unavailable"
        fi

        if grep -q "fpSessionCloseEv" "$SYMTMP"; then
            pass "FPBAuthService::fpSessionClose() symbol"
        else
            warn "fpSessionClose missing — TEE session management limited"
        fi

        # Verify BAuthService has the right structure
        echo ""
        echo "── Binary (BAuth object layout) ──"

        # ss_fingerprint_open allocates BAuthService with operator new(200)
        # Check for the 0xc8 allocation size
        if grep -q "BAuthServiceC1\|BAuthServiceC2" "$SYMTMP"; then
            pass "BAuthService constructor found"
        else
            fail "BAuthService constructor missing — object may not initialize"
        fi

        # FPBAuthService constructor (called from prepare)
        if grep -q "FPBAuthServiceC1\|FPBAuthServiceC2" "$SYMTMP"; then
            pass "FPBAuthService constructor found"
        else
            fail "FPBAuthService constructor missing — 33MB object won't initialize"
        fi

        # BAuthSensorControl (target of optHbmInterrupt at FPBAuthService+0x1f94ab8)
        if grep -q "BAuthSensorControl" "$SYMTMP"; then
            pass "BAuthSensorControl class present"
        else
            warn "BAuthSensorControl missing — optHbmInterrupt may fail silently"
        fi

        # SendCancelSignal (called when optHbmInterrupt status=2)
        if grep -q "SendCancelSignal" "$SYMTMP"; then
            pass "BAuthSensorControl::SendCancelSignal present"
        else
            warn "SendCancelSignal missing — abort path unavailable"
        fi
    fi
    rm -f "$SYMTMP"
    trap - EXIT
else
    warn "libbauthserver.so not found — cannot verify symbols"
    echo "       Searched: out/target, vendor/samsung paths"
fi

# ─── 6. Compiler flags ──────────────────────────────────────────────
echo ""
echo "── Build (compiler flags) ──"

ANDROID_BP="$HAL_DIR/Android.bp"
if [[ -f "$ANDROID_BP" ]]; then
    if grep -q '\-Werror' "$ANDROID_BP"; then
        pass "-Werror enabled (warnings are errors)"
    else
        fail "-Werror missing — warnings may hide bugs"
    fi

    if grep -q '\-Wall' "$ANDROID_BP"; then
        pass "-Wall enabled"
    else
        warn "-Wall missing"
    fi

    if grep -q '\-Wconversion' "$ANDROID_BP"; then
        pass "-Wconversion enabled (catches signedness bugs)"
    else
        warn "-Wconversion missing"
    fi

    if grep -q '\-Wnull-dereference' "$ANDROID_BP"; then
        pass "-Wnull-dereference enabled"
    else
        warn "-Wnull-dereference missing"
    fi
else
    warn "Android.bp not found"
fi

# ─── 7. On-device checks (if adb available) ─────────────────────────
echo ""
echo "── Device (live state) ──"

ICHTHYS_SERIAL="${ICHTHYS_SERIAL:-R5CR93D6A3T}"
if adb -s "$ICHTHYS_SERIAL" get-state >/dev/null 2>&1; then
    # type_check value
    TYPE_CHECK=$(adb -s "$ICHTHYS_SERIAL" shell cat /sys/class/fingerprint/fingerprint/type_check 2>/dev/null || echo "?")
    if [[ "$TYPE_CHECK" == "1" ]]; then
        pass "type_check sysfs = 1 (matches OneUI)"
    elif [[ "$TYPE_CHECK" == "8" ]]; then
        fail "type_check sysfs = 8 — BAuth WILL trigger persbds"
    else
        warn "type_check = $TYPE_CHECK (unexpected)"
    fi

    # BDS file
    BDS_SIZE=$(adb -s "$ICHTHYS_SERIAL" shell stat -c%s /data/vendor/biometrics/meta/egoptbds.dat 2>/dev/null || echo "0")
    if [[ "$BDS_SIZE" -gt 1000000 ]]; then
        pass "egoptbds.dat exists ($BDS_SIZE bytes)"
    elif [[ "$BDS_SIZE" -gt 0 ]]; then
        warn "egoptbds.dat is small ($BDS_SIZE bytes) — may be corrupted"
    else
        fail "egoptbds.dat missing or empty — no calibration data"
    fi

    BDS_FLAGS=$(adb -s "$ICHTHYS_SERIAL" shell lsattr /data/vendor/biometrics/meta/egoptbds.dat 2>/dev/null | awk '{print $1}' || echo "")
    if echo "$BDS_FLAGS" | grep -q 'i'; then
        warn "egoptbds.dat has immutable flag — blocks writes during enrollment"
    else
        pass "egoptbds.dat is writable"
    fi

    # mask_brightness sysfs
    if adb -s "$ICHTHYS_SERIAL" shell "test -w /sys/class/lcd/panel/mask_brightness" 2>/dev/null; then
        pass "mask_brightness sysfs writable"
    elif adb -s "$ICHTHYS_SERIAL" shell "test -e /sys/class/lcd/panel/mask_brightness" 2>/dev/null; then
        warn "mask_brightness exists but not writable — HBM control may fail"
    else
        fail "mask_brightness sysfs not found — cannot control HBM"
    fi

    # actual_mask_brightness sysfs (needed for HBM confirmation polling)
    if adb -s "$ICHTHYS_SERIAL" shell "test -e /sys/class/lcd/panel/actual_mask_brightness" 2>/dev/null; then
        pass "actual_mask_brightness sysfs exists (HBM polling target)"
    else
        warn "actual_mask_brightness sysfs not found — setHBM polling will skip confirmation"
    fi

    # HBM functional test: write 331, check kernel response
    echo ""
    echo "── Device (HBM functional test) ──"
    adb -s "$ICHTHYS_SERIAL" shell "echo 0 > /sys/class/lcd/panel/mask_brightness" 2>/dev/null
    sleep 0.2
    adb -s "$ICHTHYS_SERIAL" shell "dmesg -C" 2>/dev/null
    adb -s "$ICHTHYS_SERIAL" shell "echo 331 > /sys/class/lcd/panel/mask_brightness" 2>/dev/null
    sleep 0.3
    HBM_RESULT=$(adb -s "$ICHTHYS_SERIAL" shell "dmesg" 2>/dev/null | grep "ss_finger_hbm_store")
    if echo "$HBM_RESULT" | grep -q "mask_bl_level value : 331"; then
        pass "mask_brightness write accepted (finger_mask set to 1)"
    elif echo "$HBM_RESULT" | grep -q "mask already enabled"; then
        fail "mask_brightness rejected: 'mask already enabled' — stale finger_mask from boot hack"
        echo "       Kernel sde_crtc.c hack pre-set finger_mask=1 and was never cleared"
    else
        warn "unexpected mask_brightness result: $HBM_RESULT"
    fi
    # Clean up
    adb -s "$ICHTHYS_SERIAL" shell "echo 0 > /sys/class/lcd/panel/mask_brightness" 2>/dev/null

    # HAL process running
    HAL_PID=$(adb -s "$ICHTHYS_SERIAL" shell pidof android.hardware.biometrics.fingerprint-service.samsung 2>/dev/null || echo "")
    if [[ -n "$HAL_PID" ]]; then
        pass "fingerprint HAL running (pid=$HAL_PID)"
    else
        fail "fingerprint HAL not running"
    fi

    # fp/User_0 directory must exist for enrollment template storage
    if adb -s "$ICHTHYS_SERIAL" shell "test -d /data/vendor/biometrics/fp/User_0" 2>/dev/null; then
        pass "fp/User_0 directory exists (template storage)"
    else
        fail "fp/User_0 directory missing — enrollment templates can't be saved"
        echo "       HAL must create this directory before set_active_group"
    fi

    # Base biometrics directories
    for biodir in meta meta/bk info log ta ta/bta ta/dta switch type fp; do
        if adb -s "$ICHTHYS_SERIAL" shell "test -d /data/vendor/biometrics/$biodir" 2>/dev/null; then
            pass "biometrics/$biodir directory exists"
        else
            warn "biometrics/$biodir directory missing"
        fi
    done

    # Check for BAuth crashes — fp_sigh with signal != 15 (SIGTERM is normal shutdown)
    FP_CRASH_COUNT=$(adb -s "$ICHTHYS_SERIAL" logcat -d -b main -t 1000 2>/dev/null | grep -E '\[fp_sigh\] : [0-9]+' | grep -cv '\[fp_sigh\] : 15' || true)
    if [[ "$FP_CRASH_COUNT" -gt 0 ]]; then
        fail "$FP_CRASH_COUNT BAuth crash signals (non-SIGTERM fp_sigh)"
    else
        pass "no BAuth crash signals"
    fi

    # Check for error 39 in recent logs
    ERR39_COUNT=$(adb -s "$ICHTHYS_SERIAL" logcat -d -b main -t 1000 2>/dev/null | grep -c "qsapp is wrong : 39\|ret=39\|error.*39" || true)
    if [[ "$ERR39_COUNT" -gt 0 ]]; then
        warn "$ERR39_COUNT error-39 (BAD_QUALITY) events in recent logs"
    else
        pass "no error-39 events in recent logs"
    fi

    # Check SELinux denials for fingerprint
    SELINUX_DENIALS=$(adb -s "$ICHTHYS_SERIAL" logcat -d -b events 2>/dev/null | grep 'avc:  denied' | grep -ic 'fingerprint-service\|hal_fingerprint' || true)
    if [[ "$SELINUX_DENIALS" -gt 0 ]]; then
        warn "$SELINUX_DENIALS SELinux denials for fingerprint HAL"
        adb -s "$ICHTHYS_SERIAL" logcat -d -b events 2>/dev/null | grep 'avc:  denied' | grep -i 'fingerprint-service\|hal_fingerprint' | tail -3
    else
        pass "no SELinux denials for fingerprint HAL"
    fi

    # Check pointer resolution in logs
    PTR_RESOLVED=$(adb -s "$ICHTHYS_SERIAL" logcat -d -b main 2>/dev/null | grep -c "gFPBAuthService BSS addr\|FPBAuthService resolve" || true)
    if [[ "$PTR_RESOLVED" -gt 0 ]]; then
        pass "BAuth pointer resolution logged"
        adb -s "$ICHTHYS_SERIAL" logcat -d -b main 2>/dev/null | grep "gFPBAuthService BSS\|FPBAuthService resolve\|optHbmInterrupt" | tail -5
    else
        warn "no pointer resolution logs — may need HAL rebuild"
    fi
else
    warn "device $ICHTHYS_SERIAL not connected — skipping live checks"
fi

# ─── Summary ────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════"
printf "  \033[32m%d passed\033[0m  " "$PASS"
printf "\033[31m%d failed\033[0m  " "$FAIL"
printf "\033[33m%d warnings\033[0m\n" "$WARN"
echo "═══════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
    echo ""
    echo "  CRITICAL FAILURES — fix before deploying."
    exit 1
elif [[ "$WARN" -gt 0 ]]; then
    echo ""
    echo "  Warnings present — review before deploying."
    exit 2
else
    echo ""
    echo "  All clear — safe to deploy."
    exit 0
fi
