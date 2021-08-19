# COMP4905 - Honours Project, Carleton University
# Gabriel Valachi (101068875)

# Contains some definitions needed to build the recovery ramdisk.
# NOTE: Turns out this file isn't necessary, but I'll keep it in anyway.

LOCAL_PATH := $(call my-dir)

RECOVERY_API_VERSION := 3
RECOVERY_FSTAB_VERSION := 2

TARGET_RECOVERY_UI_LIB := librecovery_ui_default

include $(CLEAR_VARS)

LOCAL_MODULE := librecovery_ui_ext

LOCAL_MULTILIB := first

ifeq ($(TARGET_IS_64_BIT),true)
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/lib64
else
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/system/lib
endif

LOCAL_WHOLE_STATIC_LIBRARIES := $(TARGET_RECOVERY_UI_LIB)

LOCAL_SHARED_LIBRARIES := \
	libbase	\
	liblog	\
	librecovery_ui.recovery

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
