/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <aidl/android/hardware/keymaster/HardwareAuthToken.h>

#include <hardware/hw_auth_token.h>

#include <endian.h>

using aidl::android::hardware::keymaster::HardwareAuthToken;

namespace aidl {
namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {

inline void translate(const HardwareAuthToken& authToken, hw_auth_token_t& hat) {
    hat.challenge = static_cast<uint64_t>(authToken.challenge);
    hat.user_id = static_cast<uint64_t>(authToken.userId);
    hat.authenticator_id = static_cast<uint64_t>(authToken.authenticatorId);
    // these are in host order: translate to network order
    hat.authenticator_type = htobe32(static_cast<uint32_t>(authToken.authenticatorType));
    hat.timestamp = htobe64(static_cast<uint64_t>(authToken.timestamp.milliSeconds));
    std::copy(authToken.mac.begin(), authToken.mac.end(), hat.hmac);
}

inline void translate(const hw_auth_token_t& hat, HardwareAuthToken& authToken) {
    authToken.challenge = static_cast<int64_t>(hat.challenge);
    authToken.userId = static_cast<int64_t>(hat.user_id);
    authToken.authenticatorId = static_cast<int64_t>(hat.authenticator_id);
    // these are in network order: translate to host
    authToken.authenticatorType =
            static_cast<keymaster::HardwareAuthenticatorType>(be32toh(hat.authenticator_type));
    authToken.timestamp.milliSeconds = static_cast<int64_t>(be64toh(hat.timestamp));
    authToken.mac.insert(authToken.mac.begin(), std::begin(hat.hmac), std::end(hat.hmac));
}

}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
