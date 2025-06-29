#pragma once

#ifndef RAWHIDCONNECTION_H
#define RAWHIDCONNECTION_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint> // For uint8_t, etc.

// Required Windows header for HID functions
#include <hidsdi.h>
#pragma comment(lib, "hid.lib") // Instructs the linker to include the necessary HID library

/**
 * @class RawHidConnection
 * @brief Manages a connection to a generic Raw HID USB device.
 *
 * This class handles device discovery based on VID/PID, connection management,
 * and thread-safe data transmission. It is designed to communicate with a
 * custom device, like an Arduino flashed with Raw HID firmware, for applications
 * requiring a private, low-latency communication channel.
 */
class RawHidConnection
{
public:
    // --- Constants defining the HID Report structure ---
    // These must match the device's firmware[cite: 5].

    // The total size of an output report packet sent to the device.
    // (1 byte for the Report ID + 64 bytes for the data payload).
    static constexpr size_t RAW_HID_REPORT_SIZE = 65;

    // The Report ID for the Raw HID interface. Must be 0x00 if not specified.
    static constexpr uint8_t RAW_HID_REPORT_ID = 0x00;

    /**
     * @brief Constructor.
     * @param vendor_id The Vendor ID (VID) of the target USB device.
     * @param product_id The Product ID (PID) of the target USB device.
     */
    RawHidConnection(USHORT vendor_id, USHORT product_id);

    /**
     * @brief Destructor.
     *
     * Ensures the connection is properly closed and resources are released.
     */
    ~RawHidConnection();

    /**
     * @brief Tries to find and connect to the HID device.
     *
     * Enumerates all connected HID devices and searches for one matching the
     * VID and PID provided in the constructor.
     * @return true if the device was found and connected, false otherwise.
     */
    bool connect();

    /**
     * @brief Disconnects from the device and releases the handle.
     */
    void disconnect();

    /**
     * @brief Checks if the connection to the device is currently active.
     * @return true if connected, false otherwise.
     */
    bool isConnected() const;

    // --- Public Command Methods ---
    // These methods provide a high-level interface for sending commands.
    // The packet structure must match the protocol expected by the device firmware[cite: 5].

    void move(int x, int y);
    void click();
    void press();
    void release();

private:
    /**
     * @brief Sends a raw data packet to the device.
     *
     * This is the core communication method. It is thread-safe.
     * @param packet A pointer to the buffer containing the data to send.
     * @param size The size of the buffer.
     * @return true on success, false on failure.
     */
    bool sendPacket(const uint8_t* packet, size_t size);

private:
    // Store the VID and PID we are looking for
    const USHORT target_vid;
    const USHORT target_pid;

    // Atomic boolean for thread-safe checking of the connection status.
    std::atomic<bool> connected;

    // Handle to the open HID device, obtained via CreateFile.
    HANDLE device_handle;

    // Mutex to ensure only one thread sends a packet at a time, preventing corrupted data.
    std::mutex write_mutex;
};

#endif // RAWHIDCONNECTION_H