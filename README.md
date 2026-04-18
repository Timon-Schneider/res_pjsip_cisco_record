# res_pjsip_cisco_record

An Asterisk PJSIP module that makes the **Record soft key** on Cisco CP-8xxx IP phones work with FreePBX / Asterisk 21.

---

## The problem

When the user presses the Record key, Cisco CP-8xxx phones (CP-8811, CP-8841, CP-8851, CP-8861 …) send a `REFER` request carrying a proprietary xml body:

```xml
REFER sip:pbx SIP/2.0
Content-Type: application/x-cisco-remotecc-request+xml

<?xml version="1.0" encoding="UTF-8"?>
<x-cisco-remotecc-request>
  <softkeyeventmsg>
    <softkeyevent>StartRecording</softkeyevent>
    <dialogid>
      <callid>…</callid>
      <localtag>…</localtag>
      <remotetag>…</remotetag>
    </dialogid>
  </softkeyeventmsg>
</x-cisco-remotecc-request>
```

Asterisk has no built-in handler for this content type, which means the record button normally does nothing but generate a fast-busy response or a `501 Not Implemented`.

This module intercepts those `REFER` messages, uses the embedded SIP dialog identifiers to locate the active call leg in memory, and asynchronously attaches `MixMonitor` to save the call audio to disk. It also generates an out-of-dialog `REFER` back to the phone carrying a `<statuslineupdatereq>` to activate a "Recording" display banner.

---

## Requirements

| Component | Version tested |
|---|---|
| OS | Debian / Ubuntu (FreePBX 17 ISO) |
| FreePBX | 17 |
| Asterisk | 21.5.0 |
| Asterisk source (headers only) | 21.12.2 |
| GCC | 12+ (system default) |
| Cisco phones | CP-8811 |

---

## Installation

### Step 1 — Install build tools

```bash
apt-get update
apt-get install -y gcc make wget tar \
    libssl-dev libncurses5-dev uuid-dev \
    libjansson-dev libxml2-dev libsqlite3-dev \
    libedit-dev binutils
```

### Step 2 — Download the Asterisk source tree

The source tree is needed **for headers only** — you do not recompile Asterisk.
Use the closest available version to what FreePBX installed (21.12.2 works fine with 21.5.0):

```bash
cd /usr/src
wget https://downloads.asterisk.org/pub/telephony/asterisk/asterisk-21.12.2.tar.gz
tar xzf asterisk-21.12.2.tar.gz
```

Run `./configure` to generate `autoconfig.h` and unpack the bundled pjproject headers:

```bash
cd /usr/src/asterisk-21.12.2
./configure --with-pjproject-bundled
```

> You do **not** need to run `make`.

### Step 3 — Create `buildopts.h`

Asterisk enforces a build-option checksum between a module and the running binary.
Extract the checksum from the already-installed `res_pjsip.so`:

Write the header:

```bash
BUILDSUM=$(strings /usr/lib/x86_64-linux-gnu/asterisk/modules/res_pjsip.so \
    | grep -E "^[a-f0-9]{32}$" | head -1)
echo "Found checksum: $BUILDSUM"

cat > /usr/src/asterisk-21.12.2/include/asterisk/buildopts.h <<EOF
#ifndef _ASTERISK_BUILDOPTS_H
#define _ASTERISK_BUILDOPTS_H

#if defined(HAVE_COMPILER_ATTRIBUTE_WEAKREF)
#define __ref_undefined __attribute__((weakref));
#else
#define __ref_undefined ;
#endif

#define AST_BUILDOPT_SUM "${BUILDSUM}"

#endif /* _ASTERISK_BUILDOPTS_H */
EOF
```

Verify:

```bash
cat /usr/src/asterisk-21.12.2/include/asterisk/buildopts.h
```

### Step 4 — Copy the source file

```bash
cp res_pjsip_cisco_record.c /usr/src/asterisk-21.12.2/res/
```

OR create the source file:
```bash
nano /usr/src/asterisk-21.12.2/res/res_pjsip_cisco_record.c
```

### Step 5 — Compile

```bash
ASTSRC=/usr/src/asterisk-21.12.2
MODDIR=/usr/lib/x86_64-linux-gnu/asterisk/modules
PJROOT=${ASTSRC}/third-party/pjproject/source

gcc -fPIC -shared -g -O2 \
  -DASTERISK_REGISTER_FILE \
  -D_GNU_SOURCE \
  -DAST_MODULE_SELF_SYM=__local_ast_module_self \
  -DAST_MODULE=\"res_pjsip_cisco_record\" \
  -I${ASTSRC}/include \
  -I${PJROOT}/pjsip/include \
  -I${PJROOT}/pjlib/include \
  -I${PJROOT}/pjlib-util/include \
  -I${PJROOT}/pjmedia/include \
  -I${PJROOT}/pjnath/include \
  -o ${MODDIR}/res_pjsip_cisco_record.so \
  ${ASTSRC}/res/res_pjsip_cisco_record.c \
  && echo "COMPILE OK"
```

A successful build prints `COMPILE OK` and may produce a few harmless warnings. No errors.

To reload the module immediately after a successful compile:

```bash
asterisk -rx "module unload res_pjsip_cisco_record.so"
asterisk -rx "module load res_pjsip_cisco_record.so"
```

### Step 6 — Load the module

```bash
asterisk -rx "module load res_pjsip_cisco_record.so"
asterisk -rx "module show like cisco"
```

Expected output:

```
Module                             Description                              Use Count  Status      Support Level
res_pjsip_cisco_record.so          Cisco x-cisco-remotecc Record Handl…     0          Running     extended
```

#### Auto-load on restart

> **Do not edit `/etc/asterisk/modules.conf` directly** — FreePBX regenerates it automatically and will overwrite any changes.

FreePBX's `modules.conf` uses `autoload=yes` by default, which means every `.so` placed in the modules directory loads automatically on startup. No further configuration is needed.

---

## How it works

Cisco CP-8xxx phones do **not** internally maintain state for the Record softkey (unless directly controlled by CUCM). Every press of the Record button sends a `StartRecording` request. This module builds the toggle state internally so users get a standard "Press to Start, Press Again to Stop" experience.

1. **First Press:**
   - Phone sends `StartRecording` REFER.
   - Module responds with `202 Accepted` and a NOTIFY to unlock the softkey.
   - Module sends an out-of-dialog REFER back to the phone with a `statuslineupdatereq` xml body to display **"Recording"**.
   - Module looks up the active call channel.
   - Module runs `MixMonitor` to start saving audio into `/var/spool/asterisk/monitor/cisco-<call-id>-<epoch>.wav` and stores the call-id in a tracking list.

2. **Second Press:**
   - Phone sends another `StartRecording` REFER.
   - Module sees the active tracking state and treats it as a `StopRecording` request.
   - Module sends an out-of-dialog REFER back to the phone to display **"Recording stopped"**.
   - Module executes `StopMixMonitor` on the channel to finalize the recording.

### Compatibility with res_pjsip_cisco_conference
This module registers itself at priority `30` (`PJSIP_MOD_PRIORITY_APPLICATION - 2`).
Because `res_pjsip_cisco_conference` registers at priority `31`, the record module intercepts the `x-cisco-remotecc` REFER body *before* the conference module can silently discard it. The two modules work perfectly side-by-side.

---

## Troubleshooting

### Watch the live log

```bash
tail -f /var/log/asterisk/full | grep CiscoRecord
```

A successful recording sequence will produce output similar to:

```
[…] NOTICE[…] res_pjsip_cisco_record.c: CiscoRecord: StartRecording REFER — call-id='<call-id>'
[…] NOTICE[…] res_pjsip_cisco_record.c: CiscoRecord: starting MixMonitor on PJSIP/220-… -> cisco-<call-id>-<epoch>.wav
[…] NOTICE[…] res_pjsip_cisco_record.c: CiscoRecord: sent statuslineupdatereq REFER ('Recording')
```

And stopping it will show:
```
[…] NOTICE[…] res_pjsip_cisco_record.c: CiscoRecord: StartRecording REFER for call-id='<call-id>' but recording already active — treating as STOP
[…] NOTICE[…] res_pjsip_cisco_record.c: CiscoRecord: stopping MixMonitor on PJSIP/220-…
[…] NOTICE[…] res_pjsip_cisco_record.c: CiscoRecord: sent statuslineupdatereq REFER ('Recording stopped')
```

### `app_mixmonitor.so not loaded?`

If you press record and the logs show:
```
WARNING: CiscoRecord: MixMonitor application not found (app_mixmonitor.so not loaded?)
```
Asterisk does not have the `app_mixmonitor` module loaded. Check your Asterisk modules configuration and ensure MixMonitor is enabled and loaded.

### `buildopts.h` checksum mismatch

If Asterisk refuses to load the module with a checksum error, re-extract:

```bash
strings /usr/lib/x86_64-linux-gnu/asterisk/modules/res_pjsip.so \
    | grep -E '^[a-f0-9]{32}$' | head -1
```

Update `buildopts.h` and recompile.
