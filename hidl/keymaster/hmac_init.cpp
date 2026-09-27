/*
 * Standalone tool to initialize Samsung TEE HMAC shared secret.
 * Loads skeymast TA, gets its sharing parameters, and calls
 * computeSharedHmac to derive the HMAC key in the TEE.
 * Run after boot as root — no VINTF or service registration needed.
 */

#define LOG_TAG "samsung-hmac-init"

#include <android-base/logging.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>

using android::hardware::keymaster::V4_0::ErrorCode;
using android::hardware::keymaster::V4_0::HmacSharingParameters;
using android::hardware::keymaster::V4_0::IKeymasterDevice;
using android::hardware::keymaster::V4_0::SecurityLevel;

namespace skeymaster {
IKeymasterDevice* CreateSKeymasterDevice(SecurityLevel securityLevel);
}

int main() {
    LOG(INFO) << "Loading skeymast TA...";
    IKeymasterDevice* dev =
            skeymaster::CreateSKeymasterDevice(SecurityLevel::TRUSTED_ENVIRONMENT);
    if (!dev) {
        LOG(ERROR) << "Failed to create Samsung keymaster device";
        return 1;
    }
    LOG(INFO) << "skeymast TA loaded";

    HmacSharingParameters samsungParams;
    bool gotParams = false;

    dev->getHmacSharingParameters([&](ErrorCode ec, const HmacSharingParameters& params) {
        if (ec != ErrorCode::OK) {
            LOG(ERROR) << "getHmacSharingParameters failed: " << static_cast<int>(ec);
            return;
        }
        samsungParams = params;
        gotParams = true;
        LOG(INFO) << "Got sharing params, seed size=" << params.seed.size()
                  << " nonce size=" << params.nonce.size();
    });

    if (!gotParams) {
        LOG(ERROR) << "Could not get HMAC sharing parameters";
        return 1;
    }

    android::hardware::hidl_vec<HmacSharingParameters> allParams;
    allParams.resize(1);
    allParams[0] = samsungParams;

    bool hmacOk = false;
    dev->computeSharedHmac(allParams, [&](ErrorCode ec, const android::hardware::hidl_vec<uint8_t>& sharingCheck) {
        if (ec != ErrorCode::OK) {
            LOG(ERROR) << "computeSharedHmac failed: " << static_cast<int>(ec);
            return;
        }
        hmacOk = true;
        LOG(INFO) << "computeSharedHmac succeeded, sharingCheck size=" << sharingCheck.size();
    });

    if (!hmacOk) {
        LOG(ERROR) << "HMAC computation failed";
        return 1;
    }

    LOG(INFO) << "Samsung TEE HMAC key initialized successfully";
    return 0;
}
