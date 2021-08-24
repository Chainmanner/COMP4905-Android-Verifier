# COMP4905-Android-Verifier
A program and recovery image that are used to verify an Android installation on a bootloader-unlocked phone. Done as part of my Honours Project at Carleton University.

## License
The files under `recovery/bootloader_message/`, `recovery/minui/`, `recovery/recovery_ui/` and `recovery/res-xhdpi/`, which are needed for the recovery to be built, are from the Android Open Source Project (AOSP), which uses the Apache License 2.0.

Every other file is made by me and is released under the GNU General Public License v3.0. You're free to study, modify, and distribute every such file under the conditions of the GNU GPLv3, for any purpose whatsoever (yes, even military and intelligence purposes).

## What It Does and How to Use It
Many Android phones can have their bootloaders unlocked and custom AOSP-based operating systems installed, but unless there's a user-settable root of trust (which as far as I know is only available on the Google Pixel and some other phones), the bootloader cannot be relocked as long as a non-stock OS is installed. This leaves the phone vulnerable to evil maid attacks, which means that anybody with physical access to it could plant malware without the owner's knowledge, although the data on the device remains encrypted.

This project is an attempt to mitigate this: the user boots their phone into a custom recovery via Fastboot, it sends all the system files of the Android installation in to the verifier program running on the connected Linux PC, and the verifier checks the access-related metadata and BLAKE2b hash of every file against known-good values. If a mismatch occurs, the user gets warned about it on the PC so that they can rectify the issue or reinstall Android. Since the bootloader responsible for loading Android is almost always checked with code signing, there's no way any malware on the device can interfere with the verification process. There is some room for improvement, but overall this verification process gets the job done.

The user needs to specify the eMMC partitions on the Android device to be checked, and whether or not each partition has a filesystem. Usually these partitions include `system`, `vendor`, and `boot`, although there may be additional vendor partitions as well. If you're using a device with A/B partitioning, make sure to specify both partitions of a pair (e.g. for `system`, check both `system_a` and `system_b`). If a filesystem's present in a partition, then each file in it will be checked. If not, then only the hash of the whole partition will be checked. The reason each individual file is checked despite system partitions being mounted read-only is because it helps to know _how_ the partition got changed.

The first time the verifier is run, it will collect known-good metadata and hashes for each partition, storing the file metadata and hashes in a file called `metadata_<part>.dat` for each partition `<part>` having a filesystem and the partition hash in `hash_<nonfspart>.dat` for each partition `<nonfspart>` without a filesystem. To reset the known-good data, just delete all `metadata_*.dat` and `hash_*.dat` files.

The verifier source code is under `pc/`, while the recovery program source code is under `recovery/`. There are no configuration files; everything is hardcoded. Source file-specific definitions are in the respective source files, while values that must be known by both the verifier and the recovery program are in `verifier_constants.h`. This file is present in both `pc/` and `recovery/` and **must** be consistent; if you change one, you must also change the other one.

Since I felt the project was far too easy and I thought it would be fun to do so, I also implemented end-to-end authenticated encryption for USB comms between the verifier and the recovery. This is disabled by default; to enable it, define `SECURE_USB_COMMS` in `verifier_constants.h`. If you're unlucky enough to be using a malicious USB cable that is programmed to hide installed malware on the Android phone, this will both deter and prevent it from happening by using the Station-to-Station protocol (using ECDHE and Ed25519 in this case) for key exchange, ChaCha20 for encryption, and HMAC-SHA256 for MAC. Messages are encrypted and authenticated using encrypt-then-MAC with two keys, using HKDF to derive the encryption key from the shared secret and HKDF again to derive the MAC key from the encryption key. But unless you're as paranoid as me, don't bother enabling it, since attacks this way very unlikely to happen; authenticated encryption will slow the verification down by a not-inconsiderable amount of time. Note that transferring the recovery kernel and ramdisk with the program should still be safe, since they need to be decompressed before modification and a microcontroller that can fit in a USB cable probably doesn't have more than 1 KiB of memory.

## Building
Before you build the verifier and recovery image, if end-to-end authenticated encryption is enabled, make sure to regenerate the Ed25519 keys with the `regenkeys.sh` script.

To build the verifier, you will need OpenSSL >=1.1.0. Just use the following GCC command from the root of the source code:
```
gcc -lcrypto -o verifier pc/usb_comms_host.c pc/verifier_host.c
```

Building the recovery image is a little more complicated since you will need to use the Android build system. You will need the dependencies required to build AOSP 10, and you'll need roughly 40 GB of disk space. Fortunately, to avoid needing a full Android build environment, the TeamWin Recovery Project (TWRP) team provides some minimal build manifests at https://github.com/minimal-manifest-twrp that can be used to build any recovery image (not just a TWRP recovery).

For this recovery, since the phone's running Android 10, we will use the OmniROM minimal build manifest. Starting from the root of the source code, make a build directory, initialize it with that manifest, then sync it:
```
mkdir verifier_image_build
cd verifier_image_build
repo init --depth=1 -u git://github.com/minimal-manifest-twrp/platform_manifest_twrp_omni.git -b twrp-10.0
repo sync
```

Now setup the recovery environment and build the recovery image like so, where `<device>` is the codename for your device (e.g. `channel` for a Moto G7 Play):
```
. build/envsetup.sh
export ALLOW_MISSING_DEPENDENCIES=true
lunch omni_<device>-eng
mka recoveryimage
```

The recovery kernel and image will be found at `out/target/product/<device>/recovery.img`.


## Running
You will need a Linux PC and a bootloader-unlocked Android mobile phone to run this project. I've only run the verification system on an Arch Linux PC and on a Moto G7 Play running LineageOS 17.1, and I can't guarantee 100% that it'll work flawlessly for other PCs and phones as well.

The phone must be booted into bootloader mode, typically using a key combination (e.g. Volume Down + Power on a Moto G7 Play). Starting from the root of the source code, having followed the above build instructions, boot the recovery image via Fastboot:
```
fastboot boot ./verifier_image_build/out/target/product/<device>/recovery.img
```

When the recovery is booted and you see `VERIFIER` on the phone's screen, run the verifier:
```
./verifier
```

The first time the verifier is run, the known-good metadata and hashes will be collected and stored. Subsequent runs compare data retrieved from the device against this known-good data.

Note that although the verification process can detect if a new file is added, ie. if the number of entities in a directory has changed, it cannot detect _which_ file was added; this is an inherent limitation in the verification process.
