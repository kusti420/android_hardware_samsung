/*
 * Copyright (C) 2024-2026 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <atomic>
#include <aidl/android/hardware/biometrics/fingerprint/BnSession.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>

#include <hardware/fingerprint.h>

#include "LegacyHAL.h"
#include "LockoutTracker.h"

#define FINGERPRINT_DATA_DIR "/data/vendor/biometrics/fp/User_%d/"

using ::aidl::android::hardware::biometrics::common::DisplayState;
using ::aidl::android::hardware::biometrics::common::ICancellationSignal;
using ::aidl::android::hardware::biometrics::common::OperationContext;
using ::aidl::android::hardware::biometrics::fingerprint::PointerContext;
using ::aidl::android::hardware::keymaster::HardwareAuthToken;

namespace aidl {
namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {

void onClientDeath(void* cookie);

class Session : public BnSession {
  public:
    Session(LegacyHAL hal, int userId, std::shared_ptr<ISessionCallback> cb,
            LockoutTracker lockoutTracker);
    ndk::ScopedAStatus generateChallenge() override;
    ndk::ScopedAStatus revokeChallenge(int64_t challenge) override;
    ndk::ScopedAStatus enroll(const HardwareAuthToken& hat,
                              std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus authenticate(int64_t operationId,
                                    std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus detectInteraction(std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus enumerateEnrollments() override;
    ndk::ScopedAStatus removeEnrollments(const std::vector<int32_t>& enrollmentIds) override;
    ndk::ScopedAStatus getAuthenticatorId() override;
    ndk::ScopedAStatus invalidateAuthenticatorId() override;
    ndk::ScopedAStatus resetLockout(const HardwareAuthToken& hat) override;
    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus onPointerDown(int32_t pointerId, int32_t x, int32_t y, float minor,
                                     float major) override;
    ndk::ScopedAStatus onPointerUp(int32_t pointerId) override;
    ndk::ScopedAStatus onUiReady() override;
    ndk::ScopedAStatus authenticateWithContext(int64_t operationId, const OperationContext& context,
                                               std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus enrollWithContext(const HardwareAuthToken& hat,
                                         const OperationContext& context,
                                         std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus detectInteractionWithContext(
            const OperationContext& context, std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus onPointerDownWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus onPointerUpWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus onContextChanged(const OperationContext& context) override;
    ndk::ScopedAStatus onPointerCancelWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus setIgnoreDisplayTouches(bool shouldIgnore) override;

    ndk::ScopedAStatus cancel();
    binder_status_t linkToDeath(AIBinder* binder);
    bool isClosed();
    void notify(const fingerprint_msg_t* msg);
    void onCaptureReady();
    // IchthysOS: BAuth took a usable image (SEM CAPTURE_SUCCESS); see reportCaptureGood.
    void onCaptureSucceeded();

  private:
    LegacyHAL mHal;
    LockoutTracker mLockoutTracker;
    bool mClosed = false;
    bool mCaptureReady = false;
    // IchthysOS: this touch's capture outcome already went to the framework as an onAcquired
    // (GOOD, or a bad-quality code). Reset at every pointer-down. Set from BAuth's callback
    // threads, read there and on binder threads.
    std::atomic<bool> mCaptureReported{false};
    void reportCaptureGood(const char* why);

    void setHBM(bool enable);
    // IchthysOS: finger on/off the sensor as far as the mask HBM watchdog is concerned
    // (persist.ichthys.udfps_sync, see Session.cpp).
    static void noteFingerDown(bool down);
    Error VendorErrorFilter(int32_t error, int32_t* vendorCode);
    AcquiredInfo VendorAcquiredFilter(int32_t info, int32_t* vendorCode);
    bool checkSensorLockout();
    void clearLockout(bool clearAttemptCounter);
    void startLockoutTimer(int64_t timeout);
    void lockoutTimerExpired(uint64_t generation);

    // lockout timer
    // IchthysOS: set by binder threads and the timer thread.
    std::atomic<bool> mIsLockoutTimerStarted{false};
    std::atomic<bool> mIsLockoutTimerAborted{false};
    // IchthysOS: bumped per timer; an expired timer only acts if it is still the newest one.
    std::atomic<uint64_t> mLockoutTimerGeneration{0};

    // The user ID for which this session was created.
    int32_t mUserId;

    // Callback for talking to the framework. This callback must only be called from non-binder
    // threads to prevent nested binder calls and consequently a binder thread exhaustion.
    // Practically, it means that this callback should always be called from the worker thread.
    std::shared_ptr<ISessionCallback> mCb;

    // Binder death handler.
    AIBinder_DeathRecipient* mDeathRecipient;

    DisplayState mDisplayState;
};

}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
