#include "RawHidConnection.h"
#include <iostream>
#include <setupapi.h> // For device enumeration
#include <vector>     // For modern C++ memory management

// Define the command protocol bytes.
// These must match the Arduino sketch exactly[cite: 5].
constexpr uint8_t CMD_MOVE = 0x01;
constexpr uint8_t CMD_CLICK = 0x02;
constexpr uint8_t CMD_PRESS = 0x03;
constexpr uint8_t CMD_RELEASE = 0x04;

RawHidConnection::RawHidConnection(USHORT vendor_id, USHORT product_id)
    : target_vid(vendor_id),
    target_pid(product_id),
    connected(false),
    device_handle(INVALID_HANDLE_VALUE)
{
}

RawHidConnection::~RawHidConnection()
{
    // Ensure disconnection on object destruction (RAII principle).
    disconnect();
}

bool RawHidConnection::isConnected() const
{
    // Atomically load the connection status.
    return connected.load();
}

void RawHidConnection::disconnect()
{
    bool expected = true;
    if (connected.compare_exchange_strong(expected, false))
    {
        CloseHandle(device_handle);
        device_handle = INVALID_HANDLE_VALUE;
        std::cout << "[RawHID] Disconnected from device." << std::endl;
    }
}

bool RawHidConnection::connect()
{
    if (isConnected())
    {
        return true;
    }

    // Get the GUID for HID class devices.
    GUID hid_guid;
    HidD_GetHidGuid(&hid_guid);

    // Get a handle to a device information set for all present HID class devices.
    HDEVINFO dev_info_set = SetupDiGetClassDevs(&hid_guid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (dev_info_set == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[RawHID] Error: Could not get device info set. WinAPI Error: " << GetLastError() << std::endl;
        return false;
    }

    SP_DEVICE_INTERFACE_DATA dev_interface_data = {};
    dev_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    // Enumerate through all the HID devices
    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(dev_info_set, NULL, &hid_guid, i, &dev_interface_data); ++i)
    {
        // First, get the required buffer size for the device detail data.
        DWORD required_size = 0;
        SetupDiGetDeviceInterfaceDetail(dev_info_set, &dev_interface_data, NULL, 0, &required_size, NULL);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            continue;
        }

        // Use std::vector for automatic memory management (safer than malloc/free).
        std::vector<char> detail_data_buffer(required_size);
        PSP_DEVICE_INTERFACE_DETAIL_DATA dev_interface_detail_data =
            reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(detail_data_buffer.data());
        dev_interface_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        // Now, get the actual device detail data.
        if (!SetupDiGetDeviceInterfaceDetail(dev_info_set, &dev_interface_data, dev_interface_detail_data, required_size, NULL, NULL))
        {
            continue;
        }

        // Open the device to get its attributes. This handle is temporary.
        // The more efficient approach is to open with read/write access immediately.
        HANDLE handle = CreateFile(dev_interface_detail_data->DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (handle == INVALID_HANDLE_VALUE)
        {
            continue;
        }

        HIDD_ATTRIBUTES attributes = {};
        attributes.Size = sizeof(attributes);
        if (HidD_GetAttributes(handle, &attributes))
        {
            // Check if the VID and PID match our spoofed device.
            if (attributes.VendorID == target_vid && attributes.ProductID == target_pid)
            {
                // We found it! The handle is already open for read/write.
                device_handle = handle;
                std::cout << "[RawHID] Spoofed device found and connected!" << std::endl;
                connected = true;
                std::cout << "[RawHID] Device handle established." << std::endl;

                // Cleanup and return success.
                SetupDiDestroyDeviceInfoList(dev_info_set);
                return true;
            }
        }

        // If this is not our device, close the handle and continue the loop.
        CloseHandle(handle);
    }

    // If the loop completes, the device was not found.
    SetupDiDestroyDeviceInfoList(dev_info_set);
    std::cerr << "[RawHID] Error: Could not find spoofed device (VID: 0x" << std::hex << target_vid << ", PID: 0x" << target_pid << ")." << std::endl;
    return false;
}

bool RawHidConnection::sendPacket(const uint8_t* packet, size_t size)
{
    if (!isConnected()) return false;

    std::lock_guard<std::mutex> lock(write_mutex);

    // Use HidD_SetOutputReport for reliable communication with HID devices.
    if (!HidD_SetOutputReport(device_handle, (PVOID)packet, static_cast<ULONG>(size)))
    {
        std::cerr << "[RawHID] Error: HidD_SetOutputReport failed. WinAPI Error: " << GetLastError() << std::endl;
        disconnect();
        return false;
    }

    return true;
}

void RawHidConnection::move(int x, int y)
{
    // The packet must match the HID report size.
    uint8_t packet[RawHidConnection::RAW_HID_REPORT_SIZE] = { 0 };

    // --- Packet Structure ---
    // Byte 0: Report ID (must be 0x00 for our RawHID interface) [cite: 5]
    // Byte 1: Command Type (CMD_MOVE) [cite: 5]
    // Byte 2-3: X-Movement (16-bit signed integer) [cite: 5]
    // Byte 4-5: Y-Movement (16-bit signed integer) [cite: 5]
    // Bytes 6-64: Unused (padded with zeros)

    packet[0] = RawHidConnection::RAW_HID_REPORT_ID;
    packet[1] = CMD_MOVE;

    int16_t signed_x = static_cast<int16_t>(x);
    int16_t signed_y = static_cast<int16_t>(y);

    // Use memcpy for safe, guaranteed byte-for-byte serialization.
    memcpy(&packet[2], &signed_x, sizeof(signed_x));
    memcpy(&packet[4], &signed_y, sizeof(signed_y));

    sendPacket(packet, RawHidConnection::RAW_HID_REPORT_SIZE);
	// Log the command move action for debugging.
	std::cout << "[RawHID] Command moved: X=" << x << ", Y=" << y << std::endl;
	std::cout << "[RawHID] Packet details: " << static_cast<void*>(packet) << std::endl;
}

void RawHidConnection::click()
{
    uint8_t packet[RawHidConnection::RAW_HID_REPORT_SIZE] = { 0 };
    packet[0] = RawHidConnection::RAW_HID_REPORT_ID;
    packet[1] = CMD_CLICK;
    sendPacket(packet, RawHidConnection::RAW_HID_REPORT_SIZE);
	// Log the command click action for debugging.
    std::cout << "[RawHID] Packet details: " << static_cast<void*>(packet) << std::endl;
    std::cout << "[RawHID] Command clicked." << std::endl;
}

void RawHidConnection::press()
{
    uint8_t packet[RawHidConnection::RAW_HID_REPORT_SIZE] = { 0 };
    packet[0] = RawHidConnection::RAW_HID_REPORT_ID;
    packet[1] = CMD_PRESS;
    sendPacket(packet, RawHidConnection::RAW_HID_REPORT_SIZE);
    // Log the command press action for debugging.
    std::cout << "[RawHID] Command pressed." << std::endl;
    std::cout << "[RawHID] Packet details: " << static_cast<void*>(packet) << std::endl;
}

void RawHidConnection::release()
{
    uint8_t packet[RawHidConnection::RAW_HID_REPORT_SIZE] = { 0 };
    packet[0] = RawHidConnection::RAW_HID_REPORT_ID;
    packet[1] = CMD_RELEASE;
    sendPacket(packet, RawHidConnection::RAW_HID_REPORT_SIZE);
    // Log the command release action for debugging.
    std::cout << "[RawHID] Command released." << std::endl;
    std::cout << "[RawHID] Packet details: " << static_cast<void*>(packet) << std::endl;
}