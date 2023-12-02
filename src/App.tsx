import { useState } from 'react'
import './App.css'
import { parseRules, RuleSet } from './rules';
import { RulesPanel } from './components/RulesPanel';
import { Packet } from './packet';
import { PacketPanel } from './components/PacketPanel';
import { Firewall } from './firewall';
import { parseRoutes } from './routes';
import { parseDeviceAddresses } from './devices';
import { primitiveDeepClone } from './util';

const rulesPrompt = `iptables-save`;
const routePrompt = `ip route`;
const hostAddressesPrompt = ` ip addr show up | grep -E "UP|inet " | grep inet -B1 --no-group-separator | awk '{print $2}' | sed ':a;N;$!ba;s/:\\n/: /g'`;

const demoPacket: Packet = {
  physical: {
    inputInterface: "em2",
    outputInterface: "",
  },
  network: {
    source: "59.148.175.169",
    destination: "59.148.175.135",
  },
  transport: {
    protocol: "tcp",
    sourcePort: 63455,
    destinationPort: 443,
  }
};

function App() {
  const [ ruleText, setRuleText ] = useState("");
  const [ showText, setShowText ] = useState(true);

  const [ routeText, setRouteText ] = useState("");
  const [ showRouteText, setShowRouteText ] = useState(true);

  const [ hostAddressesText, setHostAddressesText ] = useState("");
  const [ showHostAddressesText, setShowHostAddressesText ] = useState(true);

  const [ packets, setPackets ] = useState([demoPacket]);

  let rules: RuleSet | null = null;

  try {
    rules = parseRules(ruleText);
  }
  catch (e) {}

  const hostAddresses = parseDeviceAddresses(hostAddressesText);

  const routes = parseRoutes(routeText);

  const packetResults = [];

  if (rules) {
    const fw = new Firewall(rules, hostAddresses, routes);

    for (const packet of packets) {
      let log: string[] = [];
      let packetLog: Packet[]|undefined;

      let finalPacket: Packet = primitiveDeepClone(packet);

      fw.resetLogs();

      try {
        fw.testPacket(finalPacket);
      } catch (e) {
        if (e instanceof Error) {
          fw.log(e.message);
          e.stack && fw.log(e.stack);
        }
      }

      log = fw.logBuffer;
      packetLog = fw.packetBuffer;

      const processedLog = [];
      let indent = 0;
      for (const line of log) {
        if (["ACCEPT","REJECT","DROP"].includes(line)) {
          indent = 0;
          processedLog.push(line);
        }
        else if (line.startsWith("Entering table")) {
          indent = 0;
          processedLog.push(line);
        }
        else if (line.startsWith("Entering chain")) {
          indent++;
          processedLog.push(" ".repeat(indent) + line);
          indent++;
        }
        else if (line.startsWith("Leaving chain")) {
          indent--;
          processedLog.push(" ".repeat(indent) + line);
          indent--;
        }
        else {
          processedLog.push(" ".repeat(indent) + line);
        }
      }

      packetResults.push({
        log: processedLog,
        packetLog,
        finalPacket,
      });
    }
  }

  function handleReply (finalPacket: Packet) {
    const newPacket = primitiveDeepClone(finalPacket);
    newPacket.physical.inputInterface = finalPacket.physical.outputInterface;
    newPacket.physical.outputInterface = "";
    newPacket.network.source = finalPacket.network.destination;
    newPacket.network.destination = finalPacket.network.source;
    newPacket.transport.sourcePort = finalPacket.transport.destinationPort;
    newPacket.transport.destinationPort = finalPacket.transport.sourcePort;
    setPackets(packets => [...packets, newPacket]);
  }

  return (
    <>
      <button onClick={() => setShowText(!showText)}>Edit Rules</button> <br />
      { showText &&
        <>
          <textarea
            value={ruleText}
            onChange={e => setRuleText(e.target.value)}
            style={{
              width: 800,
              height: 400,
            }}
            />
          <div style={{fontFamily:"monospace",color:"#666"}}>{rulesPrompt}</div>
        </>
      }
      <button onClick={() => setShowRouteText(!showRouteText)}>Edit Routes</button> <br />
      { showRouteText &&
        <>
          <textarea
            value={routeText}
            onChange={e => setRouteText(e.target.value)}
            style={{
              width: 300,
              height: 200,
            }}
          />
          <div style={{fontFamily:"monospace",color:"#666"}}>{routePrompt}</div>
        </>
      }
      <button onClick={() => setShowHostAddressesText(!showHostAddressesText)}>Edit Host Addresses</button> <br />
      { showHostAddressesText &&
        <>
          <textarea
            value={hostAddressesText}
            onChange={e => setHostAddressesText(e.target.value)}
            style={{
              width: 300,
              height: 200,
            }}
          />
          <div style={{fontFamily:"monospace",color:"#666"}}>{hostAddressesPrompt}</div>
        </>
      }
      <div className="Panels">
        { rules && <RulesPanel rules={rules} /> }
        <div className="Panel">
          <button onClick={() => setPackets([demoPacket])}>Reset</button>
          {
            packetResults.map((results, i) => {
              return (
                <div style={{display:"flex"}} key={i}>
                  <ol style={{flex:1,listStyle:"none",padding:0,fontFamily:"monospace",whiteSpace:"pre"}}>
                    {
                      results.log.map((line, i) => {
                        const style = {
                          background: (line.match(/^\s*!/) ? "#FFC0C0" :
                            line.startsWith("<") ? "#FFFF88" : (
                              line.startsWith("Entering table") ? "#FFFFC0" : ""
                            )
                          )
                        };

                        return <li key={i} style={style}>{line}</li>;
                      })
                    }
                  </ol>
                  <div className="Packet" style={{flex:1}}>
                    {
                      results.packetLog.map((p, i) => <div key={i}>Packet #{i}<PacketPanel packet={p} /></div>)
                    }
                    <div>
                      Final Packet
                      <PacketPanel packet={results.finalPacket} />
                    </div>
                    {
                      i === packetResults.length - 1 &&
                      <button onClick={() => handleReply(results.finalPacket)}>Send Reply</button>
                    }
                  </div>
                </div>
              );
            })
          }
          </div>
      </div>
    </>
  )
}

export default App;