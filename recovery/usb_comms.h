// TODO: Add comments to this file.

#ifndef USB_COMMS_H
#define USB_COMMS_H

bool InitFunctionFS();
void CloseFunctionFS();
ssize_t ReadFromHost(void* inBuf, size_t iNumBytes);
ssize_t WriteToHost(const void* outBuf, size_t iNumBytes);

#endif	// USB_COMMS_H
