export interface Packet {
    physical: PhysicalInfo;
    network: IPHeader;
    transport: TransportHeader;
}

interface PhysicalInfo {
    inputInterface: string;
    outputInterface: string;
}

interface IPHeader {
    source: string;
    destination: string;
}

type TransportHeader = TCPHeader | UDPHeader;

interface TCPHeader {
    protocol: "tcp";
    sourcePort: number;
    destinationPort: number;
}

interface UDPHeader {
    protocol: "udp";
    sourcePort: number;
    destinationPort: number;
}