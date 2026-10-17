package com.apparmorx.runtime

/** Internal woven ownership protocol; applications do not implement or call this interface. */
interface RemoteWorkerCancellationOwner {
    fun appArmorXGetRemoteCancellationState(): Any?
    fun appArmorXSetRemoteCancellationState(state: Any?)
}
