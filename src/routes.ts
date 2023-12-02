const ALL_ONES = 0xFFFFFFFF;

export interface Route {
    destination: {
        prefix: number;
        prefixLength: number;
    };
    dev: string;
    src?: string;
    via?: string;
};

export function parseRoutes (text: string): Route[] {
    const routes: Route[] = [];

    for (const line of text.split("\n")) {
        const route: Route = {
            destination: {
                prefix: 0,
                prefixLength: 0,
            },
            dev: "lo",
        };
        routes.push(route);

        const destination = line.substring(0, line.indexOf(" "));
        if (destination !== "default") {
            route.destination = parseSubnet(destination);
        }

        const devRegex = /dev ([a-z0-9.-]+)/i;
        const devMatch = devRegex.exec(line);
        if (!devMatch) {
            // Bad route
            console.debug("Bad route: " + line);
            continue;
        }

        route.dev = devMatch[1];

        const srcRegex = /src ([a-f0-9:.-]+)/i;
        const srcMatch = srcRegex.exec(line);
        if (srcMatch) {
            route.src = srcMatch[1];
        }

        const viaRegex = /via ([a-f0-9:.-]+)/i;
        const viaMatch = viaRegex.exec(line);
        if (viaMatch) {
            route.via = viaMatch[1];
        }
    }

    return routes;
}

export function matchSubnet (subnet: string, address: string) {
    const parsedSubnet = parseSubnet(subnet);
    const addressInt = parseIPv4Address(address);
    const mask = (ALL_ONES << (32 - parsedSubnet.prefixLength));
    return (addressInt & mask) === parsedSubnet.prefix
}

export function matchRoute (routes: Route[], address: string): Route|null {
    const addressInt = parseIPv4Address(address);

    let bestRoute: Route|null = null;

    for (const route of routes) {
        const mask = route.destination.prefixLength === 0 ? 0 :
            (ALL_ONES << (32 - route.destination.prefixLength));
        if ((addressInt & mask) === route.destination.prefix) {
            if (!bestRoute || bestRoute.destination.prefixLength < route.destination.prefixLength) {
                bestRoute = route;
            }
        }
    }

    return bestRoute;
}

/**
 * @param subnet Either subnet notation (e.g. 10.0.0.0/8) or single address (e.g. 192.168.0.1)
 */
function parseSubnet (subnet: string) {
    const [addr,prefixString] = subnet.split("/");
    const prefixLength = +prefixString || 32;
    const mask = (ALL_ONES << (32 - prefixLength));
    const prefix = parseIPv4Address(addr) & mask;

    return {
        prefix,
        prefixLength,
    }
}

function parseIPv4Address (address: string): number {
    const parts = address.split(".");
    return (+parts[0] << 24) | (+parts[1] << 16) | (+parts[2] << 8) | +parts[3];
}