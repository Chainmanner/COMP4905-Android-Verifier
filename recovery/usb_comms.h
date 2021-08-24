// COMP4905 - Honours Project, Carleton University
// Gabriel Valachi (101068875)
/*
	Copyright (C) 2021	Gabriel Valachi

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Header file for usb_comms.cpp. Contains all the function definitions needed to communicate with the verifier over USB.

#ifndef USB_COMMS_H
#define USB_COMMS_H

#include "verifier_constants.h"

// Creates the I/O endpoints and enables USB communications.
bool InitUSBComms();
// Closes the I/O file descriptors, and frees the encryption and MAC keys.
void CloseUSBComms();

// The below two functions read and write data from/to the connected verifier, after setup is done.
// numBytes is the number of bytes to read or write.

// inBuf is the buffer to store received data.
ssize_t ReadFromHost(void* inBuf, size_t iNumBytes);
// outBuf is the buffer containing the data to be sent.
ssize_t WriteToHost(const void* outBuf, size_t iNumBytes);

// NOTE: Functions only available when SECURE_USB_COMMS is defined are not exported, as they're not needed outside of usb_comms.cpp.

#endif	// USB_COMMS_H
