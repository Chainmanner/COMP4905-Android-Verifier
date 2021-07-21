// TEST CODE FOR USB COMMS
// CONTAINS POTENTIALLY DANGEROUS CODE - DO NOT USE IN FINAL VERSION

// Build using the following command:
//	gcc -o usbtest usbtest.c

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>

// Taken almost verbatim from system/core/fastboot/usb_linux.cpp of the Android source code.
int isInvalidDescriptor(void* desc, int len, unsigned type, int size)
{
	struct usb_descriptor_header *hdr = (struct usb_descriptor_header*)desc;
	if (len < size) return 1;
	if (hdr->bLength < size) return 1;
	if (hdr->bLength > len) return 1;
	if (hdr->bDescriptorType != type) return 1;
	return 0;
}

int main(int argc, char** argv)
{
	int i;

	int bytesRead;
	DIR* dirPtr;
	struct dirent* curDirEnt;

	int vendorFD, productFD;
	char curVendorPath[64], curProductPath[64];
	char vendor_char[5], product_char[5];

	int busFD, devFD;
	char curBusPath[64], curDevPath[64];
	char busNum_char[4], devNum_char[4];
	int busNum, devNum;

	char devPath[128];
	int descFD;
	char desc[1024];
	int descSize;

	int ifID, epInID, epOutID;


	// Find the device with vendor ID 0xE666 and product ID 0xE666.
	// Not the safest or most elegant way of doing so, but for a test program, it works.
	dirPtr = opendir("/sys/bus/usb/devices");
	if ( dirPtr == NULL )
	{
		perror("opendir");
		return -1;
	}
	while(1)
	{
		curDirEnt = readdir(dirPtr);
		if ( curDirEnt == NULL )
		{
			printf("verifier not found\n");
			return -1;
		}

		sprintf(curVendorPath, "/sys/bus/usb/devices/%s/idVendor", curDirEnt->d_name);
		sprintf(curProductPath, "/sys/bus/usb/devices/%s/idProduct", curDirEnt->d_name);
		vendorFD = open(curVendorPath, O_RDONLY);
		if ( vendorFD < 0 )
			continue;
		productFD = open(curProductPath, O_RDONLY);
		if ( productFD < 0 )
			continue;
		read(vendorFD, vendor_char, 4);
		read(productFD, product_char, 4);
		vendor_char[4] = '\0';
		product_char[4] = '\0';
		printf("%s %s\n", vendor_char, product_char);

		if ( !strcmp(vendor_char, "e666") && !strcmp(product_char, "e666") )
		{
			printf("verifier found\n");

			sprintf(curBusPath, "/sys/bus/usb/devices/%s/busnum", curDirEnt->d_name);
			sprintf(curDevPath, "/sys/bus/usb/devices/%s/devnum", curDirEnt->d_name);
			busFD = open(curBusPath, O_RDONLY);
			if ( busFD < 0 )
			{
				perror("open (busFD)");
				return -1;
			}
			devFD = open(curDevPath, O_RDONLY);
			if ( devFD < 0 )
			{
				perror("open (devFD)");
				return -1;
			}
			read(busFD, busNum_char, 3);
			read(devFD, devNum_char, 3);
			busNum = atoi(busNum_char);
			devNum = atoi(devNum_char);

			printf("bus: %03d | dev: %03d\n", busNum, devNum);
			sprintf(devPath, "/dev/bus/usb/%03d/%03d", busNum, devNum);
			printf("%s\n", devPath);

			break;
		}
	}

	// Get the descriptor.
	// NOTE: Make sure proper udev rules are in place.
	descFD = open(devPath, O_RDWR);
	if ( descFD < 0 )
	{
		perror("open (descFD)");
		return -1;
	}
	descSize = read(descFD, desc, sizeof(desc));

	// We already know the interface ID and I/O endpoints, but in the finished project, I'll need to actually search for them
	// to avoid potentially getting the wrong device.
	ifID = 0;
	epInID = 1 | USB_DIR_IN;
	epOutID = 1 | USB_DIR_OUT;
	if ( ioctl(descFD, USBDEVFS_CLAIMINTERFACE, &ifID) < 0 )
	{
		perror("ioctl");
		close(descFD);
		return -1;
	}

	// Write some data just to see that the USB connection works.
	const char* testData = "wow such test, very amaze\n\n";
	struct usbdevfs_bulktransfer bulk;
	bulk.ep = epOutID;
	bulk.len = strlen(testData);	// The minimum max bulk transfer size is 16 KiB (for Linux < 3.3), and this is way under that.
	bulk.data = testData;
	bulk.timeout = 0;
	if ( ioctl(descFD, USBDEVFS_BULK, &bulk) < 0 )
	{
		perror("ioctl (USBDEVFS_BULK write)");
		return -1;
	}

	return 0;
}
