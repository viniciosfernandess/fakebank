import { useEffect, useState } from "react";

type Entry = { source: string; action: string } &
  ({ status: "covered"; rule: string } | { status: "uncovered"; reason: string; summary_pt: string });
type Dynamic = { file: string; source_expression: string; action_expression: string; reason: string; summary_pt: string };
export type Coverage = { version: number; entries: Entry[]; dynamic: Dynamic[];
  rules?: { id: string; version: number; owner: string }[] };

export function DetectionCoverageTable({ coverage }: { coverage: Coverage }) {
  const [source, setSource] = useState("all");
  const dynamicSource = (item: Dynamic) => {
    const match = /^"([^"\\]+)"$/.exec(item.source_expression);
    return match?.[1] ?? "dynamic";
  };
  const sources = [...new Set([...coverage.entries.map((item) => item.source),
    ...coverage.dynamic.map(dynamicSource)])].sort();
  const entries = coverage.entries.filter((item) => source === "all" || item.source === source);
  const dynamic = coverage.dynamic.filter((item) => source === "all" || dynamicSource(item) === source);
  const rules = new Map(coverage.rules?.map((rule) => [rule.id, rule]));
  return <section className="detection-coverage" aria-label="Inventário de cobertura de detecção">
    <h3>Inventário de detecção · versão {coverage.version}</h3>
    <p>Inventário das ações de telemetria verificadas; expressões dinâmicas continuam pendentes. Isso não representa a cobertura global do SOC.</p>
    <div className="detection-coverage-summary">
      <span>{coverage.entries.filter((item) => item.status === "covered").length} com regra verificada</span>
      <span>{coverage.entries.filter((item) => item.status === "uncovered").length} sem detector direto verificado</span>
      <span>{coverage.dynamic.length} expressões dinâmicas pendentes</span>
    </div>
    <label>Fonte <select value={source} onChange={(event) => setSource(event.target.value)}>
      <option value="all">Todas</option>{sources.map((name) => <option key={name} value={name}>{name === "dynamic" ? "Fonte dinâmica" : name}</option>)}
    </select></label>
    <div className="detection-coverage-scroll"><table><thead><tr><th>Fonte</th><th>Ação</th><th>Regra ou lacuna</th></tr></thead><tbody>
      {entries.map((item) => <tr key={`${item.source}:${item.action}`}><td>{item.source}</td><td>{item.action}</td><td>{item.status === "covered" ? <>
        Regra {item.rule}{rules.get(item.rule) && <small>Versão {rules.get(item.rule)!.version} · responsável {rules.get(item.rule)!.owner}</small>}
      </> : item.summary_pt}</td></tr>)}
      {dynamic.map((item) => <tr key={`${item.file}:${item.source_expression}:${item.action_expression}`}><td>{item.source_expression}</td><td>{item.action_expression}<small>{item.file}</small></td><td>Pendente: {item.summary_pt}</td></tr>)}
    </tbody></table></div>
  </section>;
}

export function DetectionCoverage() {
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/operator/soc/detection-coverage", { cache: "no-store", signal: controller.signal })
      .then((response) => { if (!response.ok) throw new Error("Coverage unavailable"); return response.json() as Promise<Coverage>; })
      .then(setCoverage).catch(() => { if (!controller.signal.aborted) setFailed(true); });
    return () => controller.abort();
  }, []);
  if (failed) return <p role="status">Inventário de detecção indisponível.</p>;
  return coverage ? <DetectionCoverageTable coverage={coverage} /> : <p role="status">Carregando inventário de detecção…</p>;
}
