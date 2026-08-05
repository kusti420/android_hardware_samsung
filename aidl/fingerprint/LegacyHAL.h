/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <hardware/fingerprint.h>

namespace aidl {
namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {

class LegacyHAL {
  public:
    bool openHal(fingerprint_notify_t notify);
    int request(int cmd, int param);

    // Direct FPBAuthService method wrappers.
    // Samsung's HIDL service calls these C++ methods directly on the BAuth
    // singleton — they are NOT routed through ss_fingerprint_request.
    // The ET713 optical sensor requires optHbmInterrupt to know when HBM is
    // active so it can set correct exposure/gain for capture.
    int callOptHbmInterrupt(uint32_t status);   // 0=off, 1=on, 2=abort
    void callSetDisplayStatus(int status);       // 0=off, 1=on, 2=AOD
    void callSessionClose();

    // Bypass BAuth's prepare() skip logic and call
    // turnOnSensorPowerAndOpenSession directly.  prepare() checks an
    // internal state field; if non-zero it logs "BAuthSessionOpen Skip"
    // and never calls BAuth_SessionOpen (the actual TEE session-open in
    // libbauthtzcommon.so).  turnOnSensorPowerAndOpenSession itself does
    // NOT check that field — it unconditionally runs:
    //   sensor_device_control(1) → BAuth_SessionOpen → post_sensor_device_control
    // Calling it directly ensures the TEE session opens regardless of
    // whatever state the init path left behind.
    int forceSessionOpen();

    int (*ss_fingerprint_close)();
    int (*ss_fingerprint_open)(const char* id);

    int (*ss_set_notify_callback)(fingerprint_notify_t notify);
    uint64_t (*ss_fingerprint_pre_enroll)();
    int (*ss_fingerprint_enroll)(const hw_auth_token_t* hat, uint32_t gid, uint32_t timeout_sec);
    int (*ss_fingerprint_post_enroll)();
    uint64_t (*ss_fingerprint_get_auth_id)();
    int (*ss_fingerprint_cancel)();
    int (*ss_fingerprint_enumerate)();
    int (*ss_fingerprint_remove)(uint32_t gid, uint32_t fid);
    int (*ss_fingerprint_set_active_group)(uint32_t gid, const char* store_path);
    int (*ss_fingerprint_authenticate)(uint64_t operation_id, uint32_t gid);
    int (*ss_fingerprint_request)(uint32_t cmd, char* inBuf, uint32_t inBuf_length, char* outBuf,
                                  uint32_t outBuf_length, uint32_t param);

  private:
    // Resolve FPBAuthService* fresh each call from the gFPBAuthService global.
    // gFPBAuthService holds FPBAuthService* directly (33MB, scudo:secondary).
    // We store the BSS address (stable for the library lifetime) and read
    // its current value on each call.
    void* resolveFPBAuthService();

    // Address of android::gFPBAuthService in libbauthserver.so BSS.
    // This is the address of the GLOBAL VARIABLE, not its value.
    void** mGFPBAuthServiceAddr = nullptr;

    // C++ member function pointers (AArch64 calling convention: x0 = this)
    typedef int (*optHbmInterrupt_fn)(void*, uint32_t);
    typedef void (*setDisplayStatus_fn)(void*, int);
    typedef void (*sessionClose_fn)(void*);
    typedef int (*turnOnSensorPowerAndOpenSession_fn)(void*, int);

    optHbmInterrupt_fn fp_optHbmInterrupt = nullptr;
    setDisplayStatus_fn fp_setDisplayStatus = nullptr;
    sessionClose_fn fp_sessionClose = nullptr;
    turnOnSensorPowerAndOpenSession_fn fp_turnOnSensorPowerAndOpenSession = nullptr;
};

}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
