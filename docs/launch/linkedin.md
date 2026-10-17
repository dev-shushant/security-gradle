# LinkedIn post (DRAFT)

I just open-sourced something I've been building: **AppArmorX**, an Android security plugin you add with one line of Gradle.

```
plugins { id("com.apparmorx.security") version "0.1.0" }
```

No SDK to initialise. No callbacks. No "you are rooted" screen to write. At build time it:

→ injects integrity guards into your Activities, Services and Receivers
→ stops third-party SDKs from quietly reading the clipboard, device ID and location
→ rejects "trust everyone" TLS verifiers
→ derives your signing-certificate pin from your own release config
→ writes a build report you can show an auditor

The part I care about most: when a check *can't* run, it reports "unknown", never "safe".

It's v0.1. Verified on a Pixel 7 Pro and an API 35 emulator (21/21 instrumented tests), clean-room built as a Java-only app. Not yet tested on rooted devices or by an independent pentest, and no client-side protection is unbypassable. I'd genuinely like people to try to break it.

The demo app has buttons that run real attacks and show what leaked. Try it: <LINK>

#Android #MobileSecurity #Gradle #OpenSource #Kotlin
