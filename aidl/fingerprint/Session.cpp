/*
 * Copyright (C) 2024-2026 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Session.h"
#include "CancellationSignal.h"
#include "Legacy2Aidl.h"
#include "VendorConstants.h"

#include <fingerprint.sysprop.h>

#include <android-base/logging.h>

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <endian.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

using namespace ::android::fingerprint::samsung;
using namespace ::std::chrono_literals;

namespace aidl {
namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {

void onClientDeath(void* cookie) {
    LOG(INFO) << "FingerprintService has died";
    Session* session = static_cast<Session*>(cookie);
    if (session && !session->isClosed()) {
        session->close();
    }
}

Session::Session(LegacyHAL hal, int userId, std::shared_ptr<ISessionCallback> cb,
                 LockoutTracker lockoutTracker)
    : mHal(hal), mLockoutTracker(lockoutTracker), mUserId(userId), mCb(cb) {
    mDeathRecipient = AIBinder_DeathRecipient_new(onClientDeath);

    char filename[64];
    snprintf(filename, sizeof(filename), FINGERPRINT_DATA_DIR, userId);

    // BAuth stores enrollment templates in fp/User_%d/ (e.g.
    // User_0_0tmpl.dat).  On OneUI, Samsung's FingerprintService
    // creates this directory; on AOSP we must do it ourselves.
    // Without it, BAuth's mkdir attempt fails silently and
    // enrollment templates have nowhere to persist, causing
    // error 39 (BAD_QUALITY) after the TEE's internal buffer fills.
    if (::mkdir(filename, 0770) == 0) {
        LOG(INFO) << "Session: created user directory " << filename;
    } else if (errno != EEXIST) {
        LOG(ERROR) << "Session: failed to create " << filename
                   << ": " << strerror(errno);
    }

    mHal.ss_fingerprint_set_active_group(static_cast<uint32_t>(userId), filename);
}

ndk::ScopedAStatus Session::generateChallenge() {
    LOG(INFO) << "generateChallenge";

    uint64_t challenge = mHal.ss_fingerprint_pre_enroll();
    mCb->onChallengeGenerated(static_cast<int64_t>(challenge));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::revokeChallenge(int64_t challenge) {
    LOG(INFO) << "revokeChallenge";

    mHal.ss_fingerprint_post_enroll();
    mCb->onChallengeRevoked(challenge);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enroll(const HardwareAuthToken& hat,
                                   std::shared_ptr<ICancellationSignal>* out) {
    LOG(INFO) << "enroll";

    bool isOptical =
            FingerprintHalProperties::type().value_or("") == "udfps_optical";

    if (isOptical) {
        // generateChallenge (pre_enroll) fires a CBGE via controlOp(43).
        // Give it a brief window to start processing before enrollment.
        // The natural UI delay (user navigating to enrollment screen,
        // touching sensor) provides additional settling time.
        // With working optHbmInterrupt, BAuth can properly synchronize
        // HBM for dual-capture, so long CBGE waits aren't needed.
        LOG(INFO) << "enroll: brief CBGE settle";
        std::this_thread::sleep_for(500ms);

        // Set enroll type for optical sensor
        mHal.request(FINGERPRINT_REQUEST_ENROLL_TYPE, 0);
        LOG(INFO) << "enroll: set enroll type 0 (optical)";
    }

    hw_auth_token_t authToken;
    translate(hat, authToken);

    int32_t error = mHal.ss_fingerprint_enroll(&authToken, static_cast<uint32_t>(mUserId),
                                               0 /* timeoutSec */);
    if (error) {
        LOG(ERROR) << "ss_fingerprint_enroll failed: " << error;
        mCb->onError(Error::UNABLE_TO_PROCESS, static_cast<int32_t>(error));
    }

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticate(int64_t operationId,
                                         std::shared_ptr<ICancellationSignal>* out) {
    LOG(INFO) << "authenticate";

    int32_t error = mHal.ss_fingerprint_authenticate(static_cast<uint64_t>(operationId),
                                                     static_cast<uint32_t>(mUserId));
    if (error) {
        LOG(ERROR) << "ss_fingerprint_authenticate failed: " << error;
        mCb->onError(Error::UNABLE_TO_PROCESS, static_cast<int32_t>(error));
    }

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::detectInteraction(std::shared_ptr<ICancellationSignal>* out) {
    LOG(INFO) << "detectInteraction";

    LOG(INFO) << "Detect interaction is not supported";
    mCb->onError(Error::UNABLE_TO_PROCESS, 0 /* vendorCode */);

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enumerateEnrollments() {
    LOG(INFO) << "enumerateEnrollments";

    if (mHal.ss_fingerprint_enumerate) {
        int32_t error = mHal.ss_fingerprint_enumerate();
        if (error) {
            LOG(ERROR) << "ss_fingerprint_enumerate failed: " << error;
        }
    } else {
        std::vector<int> enrollments;
        char filename[64];
        snprintf(filename, sizeof(filename), FINGERPRINT_DATA_DIR, mUserId);

        DIR* directory = opendir(filename);
        if (directory) {
            struct dirent* entry;
            while ((entry = readdir(directory))) {
                int uid, fid;
                if (sscanf(entry->d_name, "User_%d_%dtmpl.dat", &uid, &fid)) {
                    if (uid == mUserId) {
                        enrollments.push_back(fid);
                    }
                }
            }
            closedir(directory);
        } else {
            LOG(WARNING) << "Failed to open " << filename;
        }

        mCb->onEnrollmentsEnumerated(enrollments);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::removeEnrollments(const std::vector<int32_t>& enrollmentIds) {
    LOG(INFO) << "removeEnrollments, size: " << enrollmentIds.size();

    for (int32_t enrollment : enrollmentIds) {
        int32_t error = mHal.ss_fingerprint_remove(static_cast<uint32_t>(mUserId),
                                                   static_cast<uint32_t>(enrollment));
        if (error) {
            LOG(ERROR) << "ss_fingerprint_remove failed: " << error;
        }
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::getAuthenticatorId() {
    LOG(INFO) << "getAuthenticatorId";

    mCb->onAuthenticatorIdRetrieved(static_cast<int64_t>(mHal.ss_fingerprint_get_auth_id()));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::invalidateAuthenticatorId() {
    LOG(INFO) << "invalidateAuthenticatorId";

    mCb->onAuthenticatorIdInvalidated(static_cast<int64_t>(mHal.ss_fingerprint_get_auth_id()));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::resetLockout(const HardwareAuthToken& /*hat*/) {
    LOG(INFO) << "resetLockout";

    clearLockout(true);
    mIsLockoutTimerAborted = true;

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::close() {
    LOG(INFO) << "close";
    // Do NOT call fpSessionClose() here. The framework destroys and recreates
    // Sessions (e.g. when FingerprintSettings reopens). Closing the BAuth TEE
    // session invalidates the HAT challenge from generateChallenge(), causing
    // BAuth_Hat_OP to fail with error 61 on the next enrollment attempt.
    // The TEE session lifetime is tied to the HAL service, not the AIDL Session.
    setHBM(false);
    mClosed = true;
    mCb->onSessionClosed();
    AIBinder_DeathRecipient_delete(mDeathRecipient);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerDown(int32_t /*pointerId*/, int32_t /*x*/, int32_t /*y*/,
                                          float /*minor*/, float /*major*/) {
    LOG(INFO) << "onPointerDown";

    // Turn on display HBM so the optical sensor has light to capture.
    // This MUST be per-touch: BAuth's later enrollment stages need the
    // illumination to cycle off between captures (unlit reference frame).
    // Holding HBM for the whole session stalls enrollment permanently at
    // the stage boundary (rem=92) — measured, see DIV-007.
    setHBM(true);

    // Send touch-down event — this is the ONLY signal OneUI's HIDL
    // service sends to BAuth on finger touch.  Do NOT call
    // optHbmInterrupt(1) or setDisplayStatus(1) here — OneUI doesn't,
    // and setting them puts BAuth's tfd HBM flag to 1 (should be 0),
    // which disrupts the internal capture flow.
    // See DIV-002 in project_fp_divergences.md.
    if (FingerprintHalProperties::request_touch_event().value_or(false)) {
        mHal.request(SEM_REQUEST_TOUCH_EVENT, 2);
    }
    checkSensorLockout();

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUp(int32_t /*pointerId*/) {
    LOG(INFO) << "onPointerUp";

    // Notify BAuth of finger lift via touch event ONLY.
    // Do NOT call optHbmInterrupt(0) or setDisplayStatus(0) here.
    // BAuth tracks HBM state internally for its dual-capture flow:
    //   Frame 1 (HBM on) → controlOp(80) → Frame 2 (HBM off)
    // Rapid optHbmInterrupt(0)→(1) toggling between touches corrupts
    // BAuth's tfd state machine (tfd shows stale 1,1,1 instead of 2,0,1),
    // causing error 70 and enrollment abort.
    // HBM-off on the display is safe — BAuth's sensor control handles
    // the actual capture exposure independently.
    if (FingerprintHalProperties::request_touch_event().value_or(false)) {
        mHal.request(SEM_REQUEST_TOUCH_EVENT, 1);
    }

    setHBM(false);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onUiReady() {
    LOG(INFO) << "onUiReady";
    // Framework handles HBM — nothing for the HAL to do here.
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticateWithContext(int64_t operationId,
                                                    const OperationContext& /*context*/,
                                                    std::shared_ptr<ICancellationSignal>* out) {
    return authenticate(operationId, out);
}

ndk::ScopedAStatus Session::enrollWithContext(const HardwareAuthToken& hat,
                                              const OperationContext& /*context*/,
                                              std::shared_ptr<ICancellationSignal>* out) {
    return enroll(hat, out);
}

ndk::ScopedAStatus Session::detectInteractionWithContext(
        const OperationContext& /*context*/, std::shared_ptr<ICancellationSignal>* out) {
    return detectInteraction(out);
}

ndk::ScopedAStatus Session::onPointerDownWithContext(const PointerContext& context) {
    int screenOffPressDelayMs = FingerprintHalProperties::screen_off_press_delay().value_or(0);

    if (screenOffPressDelayMs > 0) {
        if (context.isAod && mDisplayState == DisplayState::NO_UI) {
            std::this_thread::sleep_for(std::chrono::milliseconds(screenOffPressDelayMs));
        }
    }

    return onPointerDown(context.pointerId, static_cast<int32_t>(context.x),
                         static_cast<int32_t>(context.y), context.minor, context.major);
}

ndk::ScopedAStatus Session::onPointerUpWithContext(const PointerContext& context) {
    return onPointerUp(context.pointerId);
}

ndk::ScopedAStatus Session::onContextChanged(const OperationContext& context) {
    mDisplayState = context.displayState;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerCancelWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::setIgnoreDisplayTouches(bool /*shouldIgnore*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::cancel() {
    int32_t ret = mHal.ss_fingerprint_cancel();

    if (ret == 0) {
        setHBM(false);
        mCb->onError(Error::CANCELED, 0 /* vendorCode */);

        return ndk::ScopedAStatus::ok();
    } else {
        return ndk::ScopedAStatus::fromServiceSpecificError(ret);
    }
}

binder_status_t Session::linkToDeath(AIBinder* binder) {
    return AIBinder_linkToDeath(binder, mDeathRecipient, this);
}

bool Session::isClosed() {
    return mClosed;
}

// Translate from errors returned by traditional HAL (see fingerprint.h) to
// AIDL-compliant Error
Error Session::VendorErrorFilter(int32_t error, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (error) {
        case FINGERPRINT_ERROR_HW_UNAVAILABLE:
            return Error::HW_UNAVAILABLE;
        case FINGERPRINT_ERROR_UNABLE_TO_PROCESS:
            return Error::UNABLE_TO_PROCESS;
        case FINGERPRINT_ERROR_TIMEOUT:
            return Error::TIMEOUT;
        case FINGERPRINT_ERROR_NO_SPACE:
            return Error::NO_SPACE;
        case FINGERPRINT_ERROR_CANCELED:
            return Error::CANCELED;
        case FINGERPRINT_ERROR_UNABLE_TO_REMOVE:
            return Error::UNABLE_TO_REMOVE;
        case FINGERPRINT_ERROR_LOCKOUT: {
            *vendorCode = FINGERPRINT_ERROR_LOCKOUT;
            return Error::VENDOR;
        }
        default:
            if (error >= FINGERPRINT_ERROR_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = error - FINGERPRINT_ERROR_VENDOR_BASE;
                return Error::VENDOR;
            }
    }
    LOG(ERROR) << "Unknown error from fingerprint vendor library: " << error;
    return Error::UNABLE_TO_PROCESS;
}

// Translate acquired messages returned by traditional HAL (see fingerprint.h)
// to AIDL-compliant AcquiredInfo
AcquiredInfo Session::VendorAcquiredFilter(int32_t info, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (info) {
        case FINGERPRINT_ACQUIRED_GOOD:
            return AcquiredInfo::GOOD;
        case FINGERPRINT_ACQUIRED_PARTIAL:
            return AcquiredInfo::PARTIAL;
        case FINGERPRINT_ACQUIRED_INSUFFICIENT:
            return AcquiredInfo::INSUFFICIENT;
        case FINGERPRINT_ACQUIRED_IMAGER_DIRTY:
            return AcquiredInfo::SENSOR_DIRTY;
        case FINGERPRINT_ACQUIRED_TOO_SLOW:
            return AcquiredInfo::TOO_SLOW;
        case FINGERPRINT_ACQUIRED_TOO_FAST:
            return AcquiredInfo::TOO_FAST;
        default:
            if (info >= FINGERPRINT_ACQUIRED_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = info - FINGERPRINT_ACQUIRED_VENDOR_BASE;
                return AcquiredInfo::VENDOR;
            }
    }
    LOG(ERROR) << "Unknown acquiredmsg from fingerprint vendor library: " << info;
    return AcquiredInfo::INSUFFICIENT;
}

bool Session::checkSensorLockout() {
    LockoutMode lockoutMode = mLockoutTracker.getMode();
    if (lockoutMode == LockoutMode::PERMANENT) {
        LOG(ERROR) << "Fail: lockout permanent";
        mCb->onLockoutPermanent();
        mIsLockoutTimerAborted = true;
        return true;
    } else if (lockoutMode == LockoutMode::TIMED) {
        int64_t timeLeft = mLockoutTracker.getLockoutTimeLeft();
        LOG(ERROR) << "Fail: lockout timed " << timeLeft;
        mCb->onLockoutTimed(timeLeft);
        if (!mIsLockoutTimerStarted) startLockoutTimer(timeLeft);
        return true;
    }
    return false;
}

void Session::clearLockout(bool clearAttemptCounter) {
    mLockoutTracker.reset(clearAttemptCounter);
    mCb->onLockoutCleared();
}

void Session::startLockoutTimer(int64_t timeout) {
    mIsLockoutTimerAborted = false;
    std::function<void()> action = std::bind(&Session::lockoutTimerExpired, this);
    std::thread([timeout, action]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        action();
    }).detach();

    mIsLockoutTimerStarted = true;
}

void Session::lockoutTimerExpired() {
    if (!mIsLockoutTimerAborted) {
        clearLockout(false);
    }

    mIsLockoutTimerStarted = false;
    mIsLockoutTimerAborted = false;
}

void Session::notify(const fingerprint_msg_t* msg) {
    switch (msg->type) {
        case FINGERPRINT_ERROR: {
            int32_t vendorCode = 0;
            Error result = VendorErrorFilter(msg->data.error, &vendorCode);
            LOG(INFO) << "onError(" << static_cast<int>(result) << ")";
            setHBM(false);
            mCb->onError(result, vendorCode);
        } break;
        case FINGERPRINT_ACQUIRED: {
            int32_t vendorCode = 0;
            AcquiredInfo result =
                    VendorAcquiredFilter(msg->data.acquired.acquired_info, &vendorCode);
            LOG(INFO) << "onAcquired(" << static_cast<int>(result) << ")";
            mCb->onAcquired(result, vendorCode);
        } break;
        case FINGERPRINT_TEMPLATE_ENROLLING:
            if (FingerprintHalProperties::uses_percentage_samples().value_or(false)) {
                const_cast<fingerprint_msg_t*>(msg)->data.enroll.samples_remaining =
                        100 - msg->data.enroll.samples_remaining;
            }
            if (FingerprintHalProperties::cancel_on_enroll_completion().value_or(false)) {
                if (msg->data.enroll.samples_remaining == 0) {
                    mHal.ss_fingerprint_cancel();
                }
            }
            LOG(INFO) << "onEnrollResult(fid=" << msg->data.enroll.finger.fid
                       << ", gid=" << msg->data.enroll.finger.gid
                       << ", rem=" << msg->data.enroll.samples_remaining << ")";
            mCb->onEnrollmentProgress(static_cast<int32_t>(msg->data.enroll.finger.fid),
                                      static_cast<int32_t>(msg->data.enroll.samples_remaining));
            // Enrollment completion also tears the overlay down without a
            // finger-up, so release HBM here too (see onAuthenticated above).
            if (msg->data.enroll.samples_remaining == 0) {
                setHBM(false);
            }
            break;
        case FINGERPRINT_TEMPLATE_REMOVED: {
            LOG(INFO) << "onRemove(fid=" << msg->data.removed.finger.fid
                       << ", gid=" << msg->data.removed.finger.gid
                       << ", rem=" << msg->data.removed.remaining_templates << ")";
            std::vector<int32_t> enrollments;
            enrollments.push_back(static_cast<int32_t>(msg->data.removed.finger.fid));
            mCb->onEnrollmentsRemoved(enrollments);
        } break;
        case FINGERPRINT_AUTHENTICATED: {
            LOG(INFO) << "onAuthenticated(fid=" << msg->data.authenticated.finger.fid
                       << ", gid=" << msg->data.authenticated.finger.gid << ")";
            // A successful unlock tears the UDFPS overlay down immediately, so
            // onPointerUp never reaches us and HBM would stay on forever —
            // pinning the panel at 547 nits and making the brightness slider
            // appear dead. Always drop HBM when authentication concludes.
            setHBM(false);
            if (msg->data.authenticated.finger.fid != 0) {
                const hw_auth_token_t hat = msg->data.authenticated.hat;
                HardwareAuthToken authToken;
                translate(hat, authToken);

                mCb->onAuthenticationSucceeded(static_cast<int32_t>(
                        msg->data.authenticated.finger.fid), authToken);
                mLockoutTracker.reset(true);
            } else {
                mCb->onAuthenticationFailed();
                mLockoutTracker.addFailedAttempt();
                checkSensorLockout();
            }
        } break;
        case FINGERPRINT_TEMPLATE_ENUMERATING: {
            LOG(INFO) << "onEnumerate(fid=" << msg->data.enumerated.finger.fid
                       << ", gid=" << msg->data.enumerated.finger.gid
                       << ", rem=" << msg->data.enumerated.remaining_templates << ")";
            static std::vector<int32_t> enrollments;
            enrollments.push_back(static_cast<int32_t>(msg->data.enumerated.finger.fid));
            if (msg->data.enumerated.remaining_templates == 0) {
                mCb->onEnrollmentsEnumerated(enrollments);
                enrollments.clear();
            }
        } break;
    }
}

void Session::onCaptureReady() {
    LOG(INFO) << "onCaptureReady";
    mCaptureReady = true;
}

void Session::setHBM(bool enable) {
    // Samsung panels (S6E3FC3) have a hardware "self mask" layer that
    // creates a focused bright circle over the optical sensor area.
    // Without it, mask_brightness puts the ENTIRE display into HBM —
    // all pixels go bright, light bleeds into the sensor from surrounding
    // content, and BAuth rejects every frame as bad quality (fpop 100025).
    // The mask image (circle position/size) is loaded from kernel data
    // at boot by the panel driver (self_mask_img_write → TX_SELF_MASK_IMAGE).
    // We just need to ensure the overlay layer is enabled before setting
    // the brightness.  Disabling is unnecessary — the mask is invisible
    // when mask_brightness is 0.
    if (enable) {
        int smfd = ::open("/sys/class/lcd/panel/self_mask", O_WRONLY);
        if (smfd >= 0) {
            ::write(smfd, "1", 1);
            ::close(smfd);
            LOG(INFO) << "setHBM: self_mask enabled (hardware mask layer)";
        } else {
            LOG(WARNING) << "setHBM: failed to open self_mask: " << strerror(errno);
        }
    }

    int fd = ::open("/sys/class/lcd/panel/mask_brightness", O_WRONLY);
    if (fd >= 0) {
        ssize_t ret = ::write(fd, enable ? "331" : "0", enable ? 3 : 1);
        ::close(fd);
        LOG(INFO) << "setHBM(" << enable << ") mask_brightness write=" << ret;
    } else {
        LOG(WARNING) << "setHBM(" << enable << ") failed to open mask_brightness: "
                     << strerror(errno);
        return;
    }

    // Wait for the kernel to actually apply the brightness change.
    // ss_brightness_dcs fires sysfs_notify("actual_mask_brightness") after the
    // DSI commands complete.  We poll for that event so BAuth never captures
    // before HBM is physically on (or off).
    int afd = ::open("/sys/class/lcd/panel/actual_mask_brightness", O_RDONLY);
    if (afd >= 0) {
        // Prime the sysfs poll (initial read required before poll triggers).
        char buf[16];
        (void)::read(afd, buf, sizeof(buf));
        (void)::lseek(afd, 0, SEEK_SET);

        struct pollfd pfd;
        pfd.fd = afd;
        pfd.events = POLLPRI | POLLERR;
        int pret = ::poll(&pfd, 1, 100 /* ms — generous: one frame is ~8-16ms */);
        if (pret > 0) {
            (void)::read(afd, buf, sizeof(buf));
            LOG(INFO) << "setHBM(" << enable << ") confirmed via actual_mask_brightness";
        } else if (pret == 0) {
            LOG(WARNING) << "setHBM(" << enable << ") timed out waiting for actual_mask_brightness";
        } else {
            LOG(WARNING) << "setHBM(" << enable << ") poll error: " << strerror(errno);
        }
        ::close(afd);
    }
}

}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
