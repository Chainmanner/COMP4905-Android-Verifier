// TODO: Add comments to this file.

#ifndef USB_COMMS_H
#define USB_COMMS_H

// FIXME: TEST CODE
#include "recovery_ui/device.h"
#include "recovery_ui/stub_ui.h"
#include "recovery_ui/ui.h"

bool InitFunctionFS();
void CloseFunctionFS();
ssize_t ReadFromHost(void* inBuf, size_t iNumBytes);
ssize_t WriteToHost(const void* outBuf, size_t iNumBytes);
bool PerformECDHEKeyExchange(RecoveryUI* ui);	// FIXME: RecoveryUI used for testing

#endif	// USB_COMMS_H
