import { RuleSet, Table } from "../rules";

interface RulesPanelProps {
    rules: RuleSet,
};

export function RulesPanel ({ rules }: RulesPanelProps) {
    return (
        <div>
            raw: {Object.keys(rules.raw).length} chains<br />
            <ChainList table={rules.raw} />
            mangle: {Object.keys(rules.mangle).length} chains<br />
            <ChainList table={rules.mangle} />
            dnat: {Object.keys(rules.dnat).length} chains<br />
            <ChainList table={rules.dnat} />
            filter: {Object.keys(rules.filter).length} chains<br />
            <ChainList table={rules.filter} />
            security: {Object.keys(rules.security).length} chains<br />
            <ChainList table={rules.security} />
            snat: {Object.keys(rules.snat).length} chains<br />
            <ChainList table={rules.snat} />
        </div>
    );
}

interface ChainListProps {
    table: Table,
};

function ChainList ({ table }: ChainListProps) {
    return (
        <ul>
            {
                Object.keys(table).map(chain => <li key={chain}>{chain} (rules: {table[chain].length})</li>)
            }
        </ul>
    );
}