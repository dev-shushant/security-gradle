package com.apparmorx.runtime

import org.junit.Assert.*
import org.junit.Test

class EmulatorEvidenceTest {
    @Test fun unknownFingerprintAloneMustNotLabelPhysicalLookingDeviceEmulated() {
        assertFalse(isEmulatorFingerprint("unknown", "Pixel 7 Pro", "google", "cheetah", "cheetah", "cheetah"))
    }
    @Test fun genericBuildLabelsAloneMustNotCauseAutomaticEmulatorBlock() {
        assertFalse(isEmulatorFingerprint("generic/vendor/device:15", "Vendor Phone", "generic", "generic", "vendor_product", "qcom"))
    }
    @Test fun anEmulatorWordInModelAloneIsNotEnough() {
        assertFalse(isEmulatorFingerprint("vendor/phone/release:15", "Emulator Developer Phone", "vendor", "phone", "phone", "qcom"))
    }
    @Test fun concreteAospVirtualHardwareAndSdkProductStillDetect() {
        assertTrue(isEmulatorFingerprint("google/sdk:17", "sdk_gphone64_arm64", "google", "emu64a", "sdk_gphone64_arm64", "ranchu"))
    }
    @Test fun ambiguousLabelsRemainUnavailableRatherThanClean() {
        assertEquals(Status.UNAVAILABLE, emulatorFingerprintStatus("unknown", "Phone", "vendor", "phone", "phone", "qcom"))
        assertEquals(Status.UNAVAILABLE, emulatorFingerprintStatus("vendor/phone:15", "Emulator Developer Phone", "vendor", "phone", "phone", "qcom"))
        assertEquals(Status.UNAVAILABLE, emulatorFingerprintStatus("", "", "", "", "", ""))
    }
    @Test fun ordinaryPhysicalMetadataIsClearForThisProbeOnly() {
        assertEquals(Status.CLEAR, emulatorFingerprintStatus("google/cheetah:15", "Pixel 7 Pro", "google", "cheetah", "cheetah", "cheetah"))
    }
    @Test fun ambiguousEmulatorEvidenceAloneDoesNotRestrict() {
        val required = setOf("policy", "signing-certificate", "native-engine")
        val evidence = required.map { Evidence(it, Status.CLEAR) } + Evidence("environment-hardware", Status.UNAVAILABLE)
        assertEquals(ProtectionState.READY, decideProtection(SecuritySnapshot(1, 0, evidence), 100, required))
    }
}
