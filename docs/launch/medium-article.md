# Security you don't have to write — and the week I spent trying to break it myself (DRAFT, NOT POSTED)

*Suggested subtitle: Building a zero-integration Android security plugin, attacking it with a real rooted
device and Frida, and writing down exactly where it wins and where nothing can.*

---

## The problem with mobile app security

Most Android app protection arrives as an SDK. You add a dependency, write initialization code, register
callbacks, and build your own "this device looks compromised" screen. Teams skip it because it's work, or
they wire up half of it and call it done. Meanwhile, the third-party libraries already inside the app —
analytics, ad networks, attribution SDKs — can read the clipboard, the device ID, the last known location,
without the app's own developers ever writing a line that asked them to.

I wanted to see if that integration tax could just go away. Not "easier to integrate" — gone.

## The idea: make the build do it

AppArmorX is a single Gradle plugin. You apply it, you change nothing else, and the Android Gradle Plugin's
own bytecode-instrumentation API does the rest at compile time: security guards get woven into every
Activity, Service, BroadcastReceiver and Application lifecycle method, and calls to sensitive platform
APIs — clipboard, device identifiers, location, TLS trust managers — get rerouted through a policy layer,
*including calls made inside third-party libraries you didn't write*.

```kotlin
plugins {
    id("com.android.application")
    id("com.apparmorx.security") version "0.1.0"
}
```

That's the whole integration. No init call. No callback. No block screen you have to design yourself. The
consumer app's source tree is never touched — I verified this by decompiling the actual bytecode AGP
shipped into a sample APK and diffing it against the pre-instrumentation `.class` file.

## Three decisions that mattered more than any feature

**Unknown is never "clean."** Every check returns one of three states: `CLEAR`, `DETECTED`, or
`UNAVAILABLE`. If a probe can't run — an OEM blocks a `/proc` read, a native library fails to load — the
app reports "couldn't check," never "passed." This sounds obvious until you actually build the thing: it
is *much* easier, under deadline, to let a failed read fall through to `false` and call it a clean result.
I found and fixed three places in my own codebase this session where exactly that bug had crept in — more
on that below.

**Don't enforce on things an attacker doesn't control.** Early on, "this app permits cleartext HTTP" counted
as a threat. That would have locked out every real user of an app that deliberately allows HTTP for some
internal reason, while catching zero actual attackers. It's now an advisory finding — reported in the
build's security report, never enforced. Enforcement is reserved for evidence an attacker or a compromised
device produces, never for the app owner's own configuration choices.

**Defaults that protect, with every override visible.** A plugin that only observes by default protects no
one. One that blocks by default can brick your own debug build. So: three profiles (`DEVELOPMENT`,
`STANDARD`, `HARDENED`), debuggable builds never enforce a response against their own developer, and the
generated HTML report flags any explicit setting that's weaker than the active profile's default.

## Zero config, taken literally

Release builds need a pinned signing certificate, so a repackaged (re-signed, cracked) copy of the app gets
flagged. Asking developers to copy a SHA-256 fingerprint into a config file by hand is exactly the kind of
integration tax I was trying to remove — so the plugin reads the release `signingConfig` keystore at build
time and derives the pin itself. I checked the result against `keytool`'s own output, byte for byte.

## Then I stopped trusting my own test suite and went and attacked it

Here's the part most security tooling write-ups skip: I had a green test suite, a demo app, decent docs —
and none of it told me whether this thing actually stops anything real. So I set up a rooted Android
emulator, pushed a real `frida-server` binary to it, wrote a self-signed-cert attacker HTTPS server, and
spent a session trying to break my own plugin.

**What held up.** The dependency firewall — the part that reroutes clipboard/identifier/location/TLS calls
made by the app's *own compiled bytecode* — blocked 4 out of 4 attacks I ran against it, live, on-device.
Root detection correctly flagged a real `su` binary. A real repackaging attack (unzip a signed release,
tamper a byte, re-sign with an unrelated keystore, reinstall) correctly flipped detection from CLEAR to
DETECTED on the live app.

**What didn't.** Here's the uncomfortable one. I attached Frida to the app and, instead of using the
dependency firewall's own call sites, called Android's TLS APIs *directly* from injected code —
`SSLContext.init()` with a permissive trust manager, straight from a Frida script. That call never passes
through any of my rewritten bytecode, so there's nothing there to intercept it. Full MITM succeeded,
including against a build that had *already* detected root and moved to a restricted state. Detection
doesn't equal prevention once an attacker is running code inside your process, and I don't think any
client-side library — free or the kind that costs six figures a year — can fully close that specific door.
If a vendor tells you theirs does, ask them to show you the Frida session, not the deck.

**A bug I only found because I kept pushing.** While investigating a fix, I discovered three of my own
native checks — the ones reading `/proc/net/tcp` and `/sys/fs/selinux/enforce` to spot Frida's listener
port and SELinux's enforcement state — silently returned "clean" whenever the read itself failed. On a
real SELinux-enforcing device, that read *always* fails for an app's own sandboxed process. So those two
checks had been reporting false negatives by construction, on exactly the kind of hardened device where it
mattered most. One of them was even locked in by a wrong assertion in my own unit test suite. Fixed all
three to the same "read failure means unavailable, never clean" rule everything else in the codebase
already followed — and only found this because a real attack test didn't behave the way I expected, and I
went and found out why instead of writing it off as a fluke.

## The fix that actually worked, and the honest line around it

After confirming detection couldn't be turned into prevention for an attacker already executing code, I
added one narrowly-scoped, explicitly opt-in response: when the native engine confirms hooking or
injection evidence — never root, never a signer mismatch, only hooking — the process gets hard-killed.
Paired with a dedicated watchdog thread polling roughly every 750ms, independent of whatever's on screen,
I re-ran the exact same MITM attack to see if it mattered.

Two runs, same build, minutes apart:

- **Spawn-mode injection** (`frida -f`, where Frida launches the app itself): the attack still succeeded.
  The attacker's code is resident before my library executes a single instruction — nothing running inside
  the process can win that race, and I'm not aware of anything that can.
- **Attach-mode** (Frida attaching to an app that was already running — the far more common real-world
  pattern, since it's how you'd actually target someone's already-installed app): the attacker's script
  printed its first log line and then died — *"Failed to load script: the connection is closed."* The
  process was already gone. The watchdog had killed it before the permissive trust manager was ever
  installed. The attack was prevented, not just detected, confirmed by `logcat` and `adb shell pidof`
  going from a live PID to nothing in about a second.

That split — one scenario genuinely closed, one architecturally impossible to close — is the headline, and
I'm putting both halves in the same sentence on purpose. I asked myself the obvious follow-up: if this is
such an unclosable gap, why do companies pay serious money for commercial RASP products? The honest answer,
as far as I can tell, is that they don't actually close the spawn-mode gap either — they obfuscate their
own detection code heavily enough that it's expensive to find and patch, which is a different kind of
protection than prevention, and they lean on a layer I haven't built yet: hardware-backed attestation
(Google Play Integrity) that moves the trust decision to a separate, protected process outside the
attacker's reach entirely, verified server-side. That's on the roadmap, written down, not implemented, and
I'd rather say that plainly than imply this plugin already does it.

## What shipped, stated as what it is

- A bytecode-rewriting Gradle plugin with zero source-level integration, verified by decompiling the
  actual output.
- A dependency firewall that blocks 4/4 of the SDK data-scraping attacks I tested, against the app's own
  code paths.
- Root, repackaging, and hooking detection, each reproduced against a real attack, not assumed.
- An opt-in response that measurably prevents a live MITM attack in the realistic attach scenario, and
  measurably does not in the spawn scenario — both demonstrated, both documented.
- A three-state evidence model that treats "I couldn't check" as exactly that, after finding and fixing
  three real places where it hadn't.

Nothing here is described as unbypassable, because nothing client-side ever is. What I can say is that
every claim above has a real device, a real attack, and a log file behind it — and where something didn't
hold up, that's in the write-up too, not edited out.

---

*AppArmorX is free, source-available, and published as a v0.1 pre-release on the Gradle Plugin Portal. Full technical
validation log — every attack, every timestamp, every fix — is in the repository's
[VALIDATION.md](../VALIDATION.md) and [STATUS.md](../STATUS.md).*
