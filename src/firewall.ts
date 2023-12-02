import { HostAddresses } from "./devices";
import { Packet } from "./packet";
import { Route, matchRoute, matchSubnet } from "./routes";
import { ChainTarget, Rule, RuleSet, Table } from "./rules";
import { primitiveDeepClone } from "./util";

interface NATRecord {
    address: string;
    port: number;
}

export class Firewall {
    rules: RuleSet;
    hostAddresses: HostAddresses;
    routes: Route[];

    dnatTable: { [masqSpec: string]: NATRecord } = {};
    snatTable: { [masqSpec: string]: NATRecord } = {};

    logBuffer: string[] = [];
    packetBuffer: Packet[] = [];

    constructor (rules: RuleSet, hostAddresses: HostAddresses, routes: Route[]) {
        this.rules = rules;
        this.hostAddresses = hostAddresses;
        this.routes = routes;
    }

    log (message: string) {
        this.logBuffer.push(message);
    }

    logPacket (packet: Packet) {
        this.packetBuffer.push(primitiveDeepClone(packet));
        this.log(`!Packet modified #${this.packetBuffer.length}`);
    }

    resetLogs () {
        this.logBuffer = [];
        this.packetBuffer = [];
    }

    testPacket (packet: Packet) {
        if (packet.physical.inputInterface) {
            this.testIncomingPacket(packet);
        }
        else {
            this.testOutgoingPacket(packet);
        }
    }

    testIncomingPacket (packet: Packet) {
        // PREROUTING
        this.log("<PREROUTING>");

        // De-Masquerade/SNAT
        this.deSNAT(packet);

        let result = this.processChainInTables("PREROUTING", packet);

        if (result === ChainTarget.DROP || result === ChainTarget.REJECT) {
            this.log(["ACCEPT","REJECT","DROP"][result]);
            return;
        }

        this.log("<ROUTING>");
        if (!this.applyRouting(packet)) {
            this.log("No route to host");
            return;
        }

        if (!packet.physical.outputInterface) {
            // INPUT
            this.log("<INPUT>");

            result = this.processChainInTables("INPUT", packet);
        }
        else {
            // FORWARD
            this.log("<FORWARD>");

            result = this.processChainInTables("FORWARD", packet);

            if (result === ChainTarget.DROP || result === ChainTarget.REJECT) {
                this.log(["ACCEPT","REJECT","DROP"][result]);
                return;
            }

            // POSTROUTING
            this.log("<POSTROUTING>");

            this.deDNAT(packet);

            result = this.processChainInTables("POSTROUTING", packet);
        }


        this.log(["ACCEPT","REJECT","DROP"][result]);
    }

    testOutgoingPacket (packet: Packet) {
        this.log("<ROUTING>");
        if (!this.applyRouting(packet)) {
            this.log("No route to host");
            return;
        }

        // OUTPUT
        this.log("<OUTPUT>");

        let result = this.processChainInTables("OUTPUT", packet);

        if (result === ChainTarget.DROP || result === ChainTarget.REJECT) {
            this.log(["ACCEPT","REJECT","DROP"][result]);
            return;
        }

        // POSTROUTING
        this.log("<POSTROUTING>");

        // De-DNAT
        this.deDNAT(packet);

        result = this.processChainInTables("POSTROUTING", packet);

        this.log(["ACCEPT","REJECT","DROP"][result]);
    }

    private deDNAT(packet: Packet) {
        const dnatMasqSpec = `${packet.network.source}:${packet.transport.sourcePort}`;
        if (this.dnatTable[dnatMasqSpec]) {
            this.log("<Reverse DNAT>");
            this.logPacket(packet);
            packet.network.source = this.dnatTable[dnatMasqSpec].address;
            packet.transport.sourcePort = this.dnatTable[dnatMasqSpec].port;
        }
    }

    private deSNAT(packet: Packet) {
        const snatMasqSpec = `${packet.network.destination}:${packet.transport.destinationPort}`;
        if (this.snatTable[snatMasqSpec]) {
            this.log("<Reverse SNAT>");
            this.logPacket(packet);
            packet.network.destination = this.snatTable[snatMasqSpec].address;
            packet.transport.destinationPort = this.snatTable[snatMasqSpec].port;
        }
    }

    processChainInTables (chainName: string, packet: Packet): ChainTarget {
        for (const [tableName, table] of Object.entries(this.rules)) {
            if (table[chainName]) {
                this.log(`Entering table ${tableName}`);

                const result = this.processChain(table, chainName, packet);

                if (result != null && result !== ChainTarget.ACCEPT) {
                    return result;
                }
            }
        }

        return ChainTarget.ACCEPT;
    }

    processChain (table: Table, chainName: string, packet: Packet): ChainTarget|null {
        this.log(`Entering chain ${chainName}`);
        const chain = table[chainName];
        let i = 0;
        for (const rule of chain) {
            if (this.packetMatches(rule, packet)) {
                this.log(`Rule ${i++} match`);

                const target = rule.jump || rule.goto;

                if (!target) {
                    throw Error("Rule without a target");
                }

                switch (target) {
                    case "ACCEPT":
                        return ChainTarget.ACCEPT;

                    case "REJECT":
                        return ChainTarget.REJECT;

                    case "DROP":
                        return ChainTarget.DROP;

                    case "MARK":
                        // FIXME: do marking
                        this.log("MARK " + rule.extra["set-xmark"])
                        break;

                    case "RETURN":
                        this.log("RETURN");
                        this.log(`Leaving chain ${chainName}`);
                        return null;

                    case "DNAT":
                        this.log("DNAT");

                        const dest = rule.extra["to-destination"];
                        if (!dest) {
                            throw Error("DNAT with no to-destination");
                        }

                        this.logPacket(packet);

                        const [addr,port] = dest.split(":");

                        this.saveDNATRecord(
                            packet.network.destination,
                            packet.transport.destinationPort,
                            addr,
                            +port
                        );

                        packet.network.destination = addr;
                        packet.transport.destinationPort = +port;

                        this.log(`Leaving chain ${chainName}`);
                        return null;

                    case "SNAT":
                        // FIXME: implement
                        throw Error("Unimplemented");

                    case "MASQUERADE":
                        this.log("MASQUERADE");
                        this.logPacket(packet);

                        const out = packet.physical.outputInterface;
                        if (!this.hostAddresses[out]) {
                            throw Error(`Address not found for interface: ${out}`);
                        }

                        const masqAddress = this.hostAddresses[out].split("/")[0];
                        const sourcePort = packet.transport.sourcePort;
                        this.saveSNATRecord(packet.network.source, sourcePort, masqAddress, sourcePort);

                        packet.network.source = masqAddress;

                        this.log(`Leaving chain ${chainName}`);
                        return null;

                    default:
                        const result = this.processChain(table, target, packet);
                        if (result !== null) {
                            this.log(`Leaving chain ${chainName}`);
                            return result;
                        }
                        break;
                }

                if (rule.goto)  {
                    this.log(`Leaving chain ${chainName}`);
                    return null;
                }
            }
            else {
                this.log(`Rule ${i++} no match`);
            }
        }

        this.log(`Leaving chain ${chainName}`);

        return null;
    }

    applyRouting (packet: Packet) {
        if (this.isLocalAddress(packet.network.destination)) {
            // target is this host
            return true;
        }

        // Dummy routing
        const matchedRoute = matchRoute(this.routes, packet.network.destination);
        if (matchedRoute) {
            this.logPacket(packet);
            packet.physical.outputInterface = matchedRoute.dev;

            if (!packet.physical.inputInterface) {
                // source is this host

                if (matchedRoute.src) {
                    packet.network.source = matchedRoute.src;
                }
                else if(!packet.network.source) {
                    // FIXME: should pick address from correct subnet
                    packet.network.source = this.hostAddresses[0];
                }
            }

            return true;
        }

        return false;
    }

    private isLocalAddress (address: string) {
        return Object.values(this.hostAddresses).some(subnet => {
            const [addr] = subnet.split("/");
            return addr === address;
        });
    }

    packetMatches (rule: Rule, packet: Packet) {
        for (const match of rule.match) {
            let result;

            switch (match.module) {
                case "core":
                    switch (match.key) {
                        case "protocol":
                            result = packet.transport.protocol === match.value
                            break;

                        case "source":
                            result = matchSubnet(match.value, packet.network.source);
                            break;

                        case "destination":
                            result = matchSubnet(match.value, packet.network.destination);
                            break;

                        case "input":
                            result = packet.physical.inputInterface === match.value;
                            break;

                        case "output":
                            result = packet.physical.outputInterface === match.value;
                            break;

                        default:
                            throw Error(`[${match.module}] Unknown rule key: ${match.key}`);
                    }
                    break;

                case "comment":
                    // transparent to matching
                    result = true;
                    break;

                case "conntrack":
                    // Assume connection state is valid
                    if (match.value === "INVALID") {
                        result = false;
                    } else {
                        result = true;
                    }
                    break;

                case "mark":
                    // FIXME: implement
                    // transparent to matching
                    result = !match.invert;
                    break;

                case "tcp":
                case "udp":
                    switch (match.key) {
                        case "dport":
                            result = packet.transport.destinationPort === +match.value
                            break;

                        case "sport":
                            result = packet.transport.sourcePort === +match.value
                            break;

                        default:
                            throw Error(`[${match.module}] Unknown rule key: ${match.key}`);
                    }
                    break;

                case "addrtype":
                    // https://web.archive.org/web/20180425231633/http://security.maruhn.com/iptables-tutorial/x6330.html
                    switch (match.key) {
                        case "dst-type":
                            const dType = this.isLocalAddress(packet.network.destination) ? "LOCAL" : "UNICAST";
                            result = dType === match.value
                            break;

                        case "src-type":
                            const sType = this.isLocalAddress(packet.network.source) ? "LOCAL" : "UNICAST";
                            result = sType === match.value
                            break;

                        default:
                            throw Error(`[${match.module}] Unknown rule key: ${match.key}`);
                    }
                    break;

                case "multiport":
                    let ports;
                    if (match.value.includes(":")) {
                        const [ min, max ] = match.value.split(":");
                        ports = { min, max };
                    }
                    else {
                        ports = match.value.split(",");
                    }

                    switch (match.key) {
                        case "dports":
                            if (Array.isArray(ports)) {
                                result = ports.includes(packet.transport.destinationPort.toString());
                            }
                            else {
                                result = +ports.min <= packet.transport.destinationPort && +ports.max >= packet.transport.destinationPort;
                            }
                            break;

                        case "sports":
                            if (Array.isArray(ports)) {
                                result = ports.includes(packet.transport.sourcePort.toString());
                            }
                            else {
                                result = +ports.min <= packet.transport.sourcePort && +ports.max >= packet.transport.sourcePort;
                            }
                            break;

                        default:
                            throw Error(`[${match.module}] Unknown rule key: ${match.key}`);
                    }
                    break;

                default:
                    throw Error("Unknown rule module: " + match.module);
            }

            if (result === match.invert) {
                return false;
            }
        }

        return true;
    }

    private saveSNATRecord (
        originalAddress: string,
        originalPort: number,
        modifiedAddress: string,
        modifiedPort: number
    ) {
        this.snatTable[`${modifiedAddress}:${modifiedPort}`] = {
            address: originalAddress,
            port: originalPort
        };
    }

    private saveDNATRecord (
        originalAddress: string,
        originalPort: number,
        modifiedAddress: string,
        modifiedPort: number
    ) {
        this.dnatTable[`${modifiedAddress}:${modifiedPort}`] = {
            address: originalAddress,
            port: originalPort
        };
    }
}