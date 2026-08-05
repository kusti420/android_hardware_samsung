/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Fingerprint.h"

#include <android-base/logging.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace aidl {
namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {

bool LegacyHAL::openHal(fingerprint_notify_t notify) {
    void* handle = dlopen("libbauthserver.so", RTLD_NOW);

    if (!handle) {
        handle = dlopen("libsfp_sensor.so", RTLD_NOW);
    }

    if (handle) {
        int err;

        ss_fingerprint_close = reinterpret_cast<typeof(ss_fingerprint_close)>(
                dlsym(handle, "ss_fingerprint_close"));
        ss_fingerprint_open =
                reinterpret_cast<typeof(ss_fingerprint_open)>(dlsym(handle, "ss_fingerprint_open"));

        ss_set_notify_callback = reinterpret_cast<typeof(ss_set_notify_callback)>(
                dlsym(handle, "ss_set_notify_callback"));
        ss_fingerprint_pre_enroll = reinterpret_cast<typeof(ss_fingerprint_pre_enroll)>(
                dlsym(handle, "ss_fingerprint_pre_enroll"));
        ss_fingerprint_enroll = reinterpret_cast<typeof(ss_fingerprint_enroll)>(
                dlsym(handle, "ss_fingerprint_enroll"));
        ss_fingerprint_post_enroll = reinterpret_cast<typeof(ss_fingerprint_post_enroll)>(
                dlsym(handle, "ss_fingerprint_post_enroll"));
        ss_fingerprint_get_auth_id = reinterpret_cast<typeof(ss_fingerprint_get_auth_id)>(
                dlsym(handle, "ss_fingerprint_get_auth_id"));
        ss_fingerprint_cancel = reinterpret_cast<typeof(ss_fingerprint_cancel)>(
                dlsym(handle, "ss_fingerprint_cancel"));
        ss_fingerprint_enumerate = reinterpret_cast<typeof(ss_fingerprint_enumerate)>(
                dlsym(handle, "ss_fingerprint_enumerate"));
        ss_fingerprint_remove = reinterpret_cast<typeof(ss_fingerprint_remove)>(
                dlsym(handle, "ss_fingerprint_remove"));
        ss_fingerprint_set_active_group = reinterpret_cast<typeof(ss_fingerprint_set_active_group)>(
                dlsym(handle, "ss_fingerprint_set_active_group"));
        ss_fingerprint_authenticate = reinterpret_cast<typeof(ss_fingerprint_authenticate)>(
                dlsym(handle, "ss_fingerprint_authenticate"));
        ss_fingerprint_request = reinterpret_cast<typeof(ss_fingerprint_request)>(
                dlsym(handle, "ss_fingerprint_request"));

        if ((err = ss_fingerprint_open(nullptr)) != 0) {
            LOG(ERROR) << "Can't open fingerprint, error: " << err;
            return false;
        }

        if ((err = ss_set_notify_callback(notify)) != 0) {
            LOG(ERROR) << "Can't register fingerprint module callback, error: " << err;
            return false;
        }

        // Store the BSS address of gFPBAuthService for lazy resolution.
        // gFPBAuthService holds FPBAuthService* directly — the 33MB object
        // allocated by BAuthService::prepare(new(0x1f95000)).
        // Verified by memory map: scudo:secondary region from this pointer
        // to region end = exactly 0x1f95000 bytes.
        // optHbmInterrupt operates on FPBAuthService as this, accessing
        // +0x1f94aaa (status) and +0x1f94ab8 (BAuthSensorControl*).
        mGFPBAuthServiceAddr = reinterpret_cast<void**>(
                dlsym(handle, "_ZN7android15gFPBAuthServiceE"));
        if (mGFPBAuthServiceAddr) {
            LOG(INFO) << "gFPBAuthService BSS addr: " << mGFPBAuthServiceAddr
                      << " current value: " << *mGFPBAuthServiceAddr;
            void* fpb = resolveFPBAuthService();
            LOG(INFO) << "Initial FPBAuthService resolve: " << fpb;
        } else {
            LOG(WARNING) << "Could not find gFPBAuthService symbol";
        }

        fp_optHbmInterrupt = reinterpret_cast<optHbmInterrupt_fn>(
                dlsym(handle, "_ZN7android14FPBAuthService15optHbmInterruptEj"));
        fp_setDisplayStatus = reinterpret_cast<setDisplayStatus_fn>(
                dlsym(handle, "_ZN7android14FPBAuthService18set_display_statusEi"));
        fp_sessionClose = reinterpret_cast<sessionClose_fn>(
                dlsym(handle, "_ZN7android14FPBAuthService14fpSessionCloseEv"));
        fp_turnOnSensorPowerAndOpenSession =
                reinterpret_cast<turnOnSensorPowerAndOpenSession_fn>(dlsym(
                        handle,
                        "_ZN7android14FPBAuthService31turnOnSensorPowerAndOpenSessionEi"));

        LOG(INFO) << "BAuth direct methods: optHbmInterrupt="
                  << (fp_optHbmInterrupt ? "OK" : "MISSING")
                  << " setDisplayStatus="
                  << (fp_setDisplayStatus ? "OK" : "MISSING")
                  << " sessionClose="
                  << (fp_sessionClose ? "OK" : "MISSING")
                  << " turnOnSensorPowerAndOpenSession="
                  << (fp_turnOnSensorPowerAndOpenSession ? "OK" : "MISSING");

        // Ensure base biometrics directory tree exists.
        // On OneUI, Samsung's framework creates these; on AOSP they may be
        // missing, causing BAuth's internal mkdir to fail silently and
        // enrollment to break (no place to store templates / metadata).
        static const char* kBioDirs[] = {
            "/data/vendor/biometrics",
            "/data/vendor/biometrics/fp",
            "/data/vendor/biometrics/meta",
            "/data/vendor/biometrics/meta/bk",
            "/data/vendor/biometrics/info",
            "/data/vendor/biometrics/log",
            "/data/vendor/biometrics/ta",
            "/data/vendor/biometrics/ta/bta",
            "/data/vendor/biometrics/ta/dta",
            "/data/vendor/biometrics/switch",
            "/data/vendor/biometrics/type",
        };
        for (const char* dir : kBioDirs) {
            if (::mkdir(dir, 0770) == 0) {
                LOG(INFO) << "Created biometrics dir: " << dir;
            }
            // EEXIST is fine — directory already exists.
        }

        // Clear any stale finger_mask state left by boot-time display code.
        // The kernel's sde_crtc previously set finger_mask=1 at first frame,
        // which causes ss_finger_hbm_store to reject the first real HBM write
        // ("mask already enabled").  Writing 0 here resets it so the HAL's
        // setHBM(true) works on the very first touch.
        {
            int fd = ::open("/sys/class/lcd/panel/mask_brightness", O_WRONLY);
            if (fd >= 0) {
                (void)::write(fd, "0", 1);
                ::close(fd);
                LOG(INFO) << "mask_brightness reset to 0 (clear stale boot state)";
            }
        }

        return true;
    }

    return false;
}

int LegacyHAL::request(int cmd, int param) {
    int result = ss_fingerprint_request(static_cast<uint32_t>(cmd), nullptr, 0, nullptr, 0,
                                        static_cast<uint32_t>(param));
    LOG(INFO) << "request(cmd=" << cmd << ", param=" << param << ", result=" << result << ")";
    return result;
}

void* LegacyHAL::resolveFPBAuthService() {
    if (!mGFPBAuthServiceAddr || !*mGFPBAuthServiceAddr) {
        return nullptr;
    }
    // gFPBAuthService holds FPBAuthService* directly (the 33MB object).
    // Verified by memory map analysis: the global's value points to the
    // start of a scudo:secondary allocation whose size (0x1f95000) exactly
    // matches the FPBAuthService new() in BAuthService::prepare().
    // No intermediate BAuthService dereference needed.
    return *mGFPBAuthServiceAddr;
}

int LegacyHAL::callOptHbmInterrupt(uint32_t status) {
    void* service = resolveFPBAuthService();
    if (service && fp_optHbmInterrupt) {
        LOG(INFO) << "optHbmInterrupt(" << status << ") service=" << service;
        int ret = fp_optHbmInterrupt(service, status);
        LOG(INFO) << "optHbmInterrupt(" << status << ") = " << ret;
        return ret;
    }
    LOG(WARNING) << "optHbmInterrupt unavailable (service=" << service
                 << " fn=" << reinterpret_cast<void*>(fp_optHbmInterrupt) << ")";
    return -1;
}

void LegacyHAL::callSetDisplayStatus(int status) {
    void* service = resolveFPBAuthService();
    if (service && fp_setDisplayStatus) {
        fp_setDisplayStatus(service, status);
        LOG(INFO) << "set_display_status(" << status << ")";
    }
}

void LegacyHAL::callSessionClose() {
    void* service = resolveFPBAuthService();
    if (service && fp_sessionClose) {
        fp_sessionClose(service);
        LOG(INFO) << "fpSessionClose()";
    }
}

int LegacyHAL::forceSessionOpen() {
    void* service = resolveFPBAuthService();
    if (!service) {
        LOG(ERROR) << "forceSessionOpen: FPBAuthService not resolved";
        return -1;
    }
    if (!fp_turnOnSensorPowerAndOpenSession) {
        LOG(ERROR) << "forceSessionOpen: turnOnSensorPowerAndOpenSession not resolved";
        return -2;
    }

    // Call turnOnSensorPowerAndOpenSession directly, bypassing
    // prepare()'s internal state check that causes "BAuthSessionOpen Skip".
    // This function unconditionally runs:
    //   sensor_device_control(1) → BAuth_SessionOpen → post_sensor_device_control
    int ret = fp_turnOnSensorPowerAndOpenSession(service, 0);
    LOG(INFO) << "forceSessionOpen: result=" << ret;
    return ret;
}

}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
