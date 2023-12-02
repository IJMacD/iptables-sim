// Useful ref: https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture

export function parseRules(ruleText: string): RuleSet {
  const ruleSet: RuleSet = makeEmptyRuleSet();

  const lines = ruleText.split("\n");

  let currentTable: keyof RuleSet = "raw";

  for (const line of lines) {
    if (line.length === 0) {
      continue;
    }

    if (line[0] === "*") {
      const table = line.substring(1);
      if (table in ruleSet) {
        currentTable = table as keyof RuleSet;

        console.debug("Processing table " + currentTable);
      }
    }
    else if (line[0] === ":") {
      const chain = line.substring(1, line.indexOf(" "));

      ruleSet[currentTable][chain] = [];

      console.debug(`Created chain ${chain} in table ${currentTable}`);
    }
    else if (line[0] === "#") {
      // comment
    }
    else if (line === "COMMIT") {
      // commit
    }
    else {
      if (line[0] !== "-") {
        throw Error("Some unexpected parsing condition. line: [" + line + "]");
      }

      const regex = /(!\s+)?(-[a-z]|--[a-z-]+)\s+("[^"]*"|\S+)/gi;

      const matches = line.matchAll(regex);

      let currentMatchModule: string|null = null;

      const rule: Rule = {
        match: [],
        extra: {},
      };

      for (const match of matches) {
        const invert = !!match[1];

        const op = match[2];
        const value = match[3];

        switch (op) {
          case "-A":
            if (!ruleSet[currentTable][value]) {
              // throw Error(`Unable to find chain ${value} in table ${currentTable}`);
              ruleSet[currentTable][value] = [];
              console.debug(`Created implicit chain ${value} in table ${currentTable}`);
            }
            const chain = ruleSet[currentTable][value];
            chain.push(rule);
            break;

          case "-j":
            rule.jump = value;
            currentMatchModule = null;
            break;

          case "-g":
            rule.goto = value;
            currentMatchModule = null;
            break;

          case "-p":
            rule.match.push({
              module: "core",
              invert,
              key: "protocol",
              value,
            });
            break;

          case "-s":
            rule.match.push({
              module: "core",
              invert,
              key: "source",
              value,
            });
            break;

          case "-d":
            rule.match.push({
              module: "core",
              invert,
              key: "destination",
              value,
            });
            break;

          case "-i":
            rule.match.push({
              module: "core",
              invert,
              key: "input",
              value,
            });
            break;

          case "-o":
            rule.match.push({
              module: "core",
              invert,
              key: "output",
              value,
            });
            break;

          case "-m":
            currentMatchModule = value;
            break;

          default:
            if (currentMatchModule) {
              rule.match.push({
                module: currentMatchModule,
                invert,
                key: op.replace(/^-+/, ""),
                value,
              });
              currentMatchModule = null;
            }
            else {
              rule.extra[op.replace(/^-+/, "")] = value;
            }
            break;
        }
      }
    }
  }

  return ruleSet;
}

export interface RuleSet {
  raw:      Table;
  mangle:   Table;
  dnat:     Table;
  filter:   Table;
  security: Table;
  snat:     Table;
}

export interface Table {
  [chain: string]: Rule[];
}

export interface Rule {
  jump?: string;
  goto?: string;
  setMark?: string;

  match: MatchRule[];

  comment?: string;
  extra: { [key: string]: string };
}

export interface MatchRule {
  module: string;
  invert: boolean;
  key: string;
  value: string;
}

export enum ChainTarget {
  ACCEPT,
  REJECT,
  DROP,
};

// enum ConnectionState {
//   NEW,
//   ESTABLISHED,
//   RELATED,
//   INVALID,
//   UNTRACKED,
//   SNAT,
//   DNAT,
// }
//
// interface ConnTrackMatchRule extends MatchRule {
//   connectionStates: ConnectionState[];
// }

function makeEmptyRuleSet(): RuleSet {
  return {
    raw: {
      PREROUTING: [],
      OUTPUT: [],
    },
    mangle: {
      PREROUTING: [],
      INPUT: [],
      FORWARD: [],
      OUTPUT: [],
      POSTROUTING: [],
    },
    dnat: {
      PREROUTING: [],
      OUTPUT: [],
    },
    filter: {
      INPUT: [],
      FORWARD: [],
      OUTPUT: [],
    },
    security: {
      INPUT: [],
      FORWARD: [],
      OUTPUT: [],
    },
    snat: {
      INPUT: [],
      POSTROUTING: [],
    },
  };
}
