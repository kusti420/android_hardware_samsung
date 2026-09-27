#define LOG_TAG "samsung-sharedsecret"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <aidl/android/hardware/security/sharedsecret/BnSharedSecret.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>

using aidl::android::hardware::security::sharedsecret::BnSharedSecret;
using aidl::android::hardware::security::sharedsecret::SharedSecretParameters;
using android::hardware::keymaster::V4_0::ErrorCode;
using android::hardware::keymaster::V4_0::HmacSharingParameters;
using android::hardware::keymaster::V4_0::IKeymasterDevice;
using android::hardware::keymaster::V4_0::SecurityLevel;

namespace skeymaster {
IKeymasterDevice* CreateSKeymasterDevice(SecurityLevel securityLevel);
}

class SamsungSharedSecret : public BnSharedSecret {
public:
    SamsungSharedSecret() {
        LOG(INFO) << "Loading Samsung skeymast TA";
        mDevice = skeymaster::CreateSKeymasterDevice(SecurityLevel::TRUSTED_ENVIRONMENT);
        if (!mDevice) {
            LOG(ERROR) << "Failed to create Samsung keymaster device";
        } else {
            LOG(INFO) << "Samsung skeymast TA loaded";
        }
    }

    ::ndk::ScopedAStatus getSharedSecretParameters(SharedSecretParameters* out) override {
        if (!mDevice) {
            return ndk::ScopedAStatus::fromServiceSpecificError(-1);
        }

        bool ok = false;
        mDevice->getHmacSharingParameters([&](ErrorCode ec, const HmacSharingParameters& params) {
            if (ec == ErrorCode::OK) {
                out->seed.assign(params.seed.begin(), params.seed.end());
                out->nonce.assign(params.nonce.data(),
                                  params.nonce.data() + params.nonce.size());
                ok = true;
                LOG(INFO) << "getSharedSecretParameters: seed=" << params.seed.size()
                          << " nonce=" << params.nonce.size();
            } else {
                LOG(ERROR) << "getHmacSharingParameters failed: " << static_cast<int>(ec);
            }
        });

        if (!ok) {
            return ndk::ScopedAStatus::fromServiceSpecificError(-1);
        }
        return ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus computeSharedSecret(
            const std::vector<SharedSecretParameters>& params,
            std::vector<uint8_t>* out) override {
        if (!mDevice) {
            return ndk::ScopedAStatus::fromServiceSpecificError(-1);
        }

        android::hardware::hidl_vec<HmacSharingParameters> hidlParams;
        hidlParams.resize(params.size());
        for (size_t i = 0; i < params.size(); i++) {
            hidlParams[i].seed.setToExternal(
                    const_cast<uint8_t*>(params[i].seed.data()), params[i].seed.size());
            hidlParams[i].nonce = {};
            if (params[i].nonce.size() == sizeof(hidlParams[i].nonce)) {
                memcpy(hidlParams[i].nonce.data(), params[i].nonce.data(), params[i].nonce.size());
            }
        }

        LOG(INFO) << "computeSharedSecret with " << params.size() << " participants";

        bool ok = false;
        mDevice->computeSharedHmac(hidlParams,
                [&](ErrorCode ec, const android::hardware::hidl_vec<uint8_t>& sharingCheck) {
            if (ec == ErrorCode::OK) {
                out->assign(sharingCheck.begin(), sharingCheck.end());
                ok = true;
                LOG(INFO) << "computeSharedHmac succeeded, check=" << sharingCheck.size();
            } else {
                LOG(ERROR) << "computeSharedHmac failed: " << static_cast<int>(ec);
            }
        });

        if (!ok) {
            return ndk::ScopedAStatus::fromServiceSpecificError(-1);
        }
        return ndk::ScopedAStatus::ok();
    }

private:
    IKeymasterDevice* mDevice = nullptr;
};

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    auto service = ndk::SharedRefBase::make<SamsungSharedSecret>();
    const std::string instance =
            std::string(SamsungSharedSecret::descriptor) + "/samsung";
    auto status = AServiceManager_addService(service->asBinder().get(), instance.c_str());
    if (status != STATUS_OK) {
        LOG(ERROR) << "Failed to register ISharedSecret/samsung: " << status;
        return 1;
    }

    LOG(INFO) << "Samsung SharedSecret service registered as " << instance;
    ABinderProcess_joinThreadPool();
    return 0;
}
