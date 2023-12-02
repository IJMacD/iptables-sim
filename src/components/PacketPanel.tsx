import { Packet } from "../packet";

interface PacketPanelProps {
    packet: Packet,
};

export function PacketPanel ({ packet }: PacketPanelProps) {
    return (
        <div>
            <dl style={{background:"#FFC0C0",border:"1px solid #803030"}}>
                <dt>Input Interface</dt>
                <dd>{packet.physical.inputInterface}</dd>
                <dt>Output Interface</dt>
                <dd>{packet.physical.outputInterface}</dd>
            </dl>
            <dl style={{background:"#C0C0FF",border:"1px solid #303080"}}>
                <dt>Source Address</dt>
                <dd>{packet.network.source}</dd>
                <dt>Destination Address</dt>
                <dd>{packet.network.destination}</dd>
            </dl>
            <dl style={{background:"#C0FFC0",border:"1px solid #308030"}}>
                <dt>Protocol</dt>
                <dd>{packet.transport.protocol}</dd>
                <dt>Source Port</dt>
                <dd>{packet.transport.sourcePort}</dd>
                <dt>Destination Port</dt>
                <dd>{packet.transport.destinationPort}</dd>
            </dl>
        </div>
    )
}