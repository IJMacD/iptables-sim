export interface HostAddresses {
    [device: string]: string;
}

/**
 *
 * @param text input format:
 * ```
 *      lo: 127.0.0.1/8
 *      eth0: 10.0.0.1/24
 * ```
 * @returns
 */
export function parseDeviceAddresses (text: string): HostAddresses {
    const devices: HostAddresses = {};

    for (const line of text.split("\n")) {
        if (line.length === 0) {
            continue;
        }

        const [device, address] = line.split(/:\s*/);
        devices[device] = address;
    }

    return devices;
}