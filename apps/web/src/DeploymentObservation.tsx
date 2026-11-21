export interface DeploymentObservationData {
  run_id: string;
  started_at: string;
  state: "watching" | "passed" | "failed" | "rolled_back";
  reason: string | null;
  baseline_5xx: number;
  baseline_p95_ms: number;
  samples: { at: string; requests: number; errors_5xx: number;
    honest_requests: number; wrongly_blocked: number; p95_ms: number }[];
}

const stateLabel: Record<DeploymentObservationData["state"], string> = {
  watching: "Em observação", passed: "Observação aprovada",
  failed: "Falha detectada", rolled_back: "Correção revertida",
};
const reasonLabel: Record<string, string> = {
  health: "saúde", http_5xx: "erros HTTP", latency: "latência",
  honest_probe: "prova honesta", false_block: "falso bloqueio",
  ledger_drift: "conciliação", unrelated_critical: "alerta crítico",
};

function MetricChart({ label, values, format, reference }: {
  label: string; values: (number | null)[]; format: (value: number) => string;
  reference?: number;
}) {
  const measured = values.flatMap((value) => value === null ? [] : [value]);
  const maximum = Math.max(0.001, ...measured, reference ?? 0) * 1.1;
  const segments: { x: number; y: number }[][] = [];
  values.forEach((value, index) => {
    if (value === null) return;
    if (index === 0 || values[index - 1] === null) segments.push([]);
    segments.at(-1)!.push({ x: values.length < 2 ? 160 : 8 + index * 304 / (values.length - 1),
      y: 72 - value / maximum * 60 });
  });
  const lastPoint = segments.at(-1)?.at(-1);
  const latest = measured.at(-1);
  return <div className="soc-observation-metric">
    <div><strong>{label}</strong><span>{latest === undefined ? "Sem tráfego" : format(latest)}</span></div>
    <svg viewBox="0 0 320 84" role="img" aria-label={`${label}: ${latest === undefined ?
      "sem medição" : format(latest)}`} preserveAspectRatio="none">
      <path d="M8 72 H312" className="soc-observation-axis" />
      {reference !== undefined && <path d={`M8 ${72 - reference / maximum * 60} H312`}
        className="soc-observation-reference" />}
      {segments.filter((segment) => segment.length > 1).map((segment, index) =>
        <polyline key={index} points={segment.map((point) =>
          `${point.x},${point.y}`).join(" ")} fill="none" className="soc-observation-line" />)}
      {lastPoint && <circle cx={lastPoint.x} cy={lastPoint.y} r="3"
        className="soc-observation-point" />}
    </svg>
  </div>;
}

export function DeploymentObservation({ deployment }: { deployment: DeploymentObservationData }) {
  const samples = deployment.samples;
  const errorRate = samples.map((sample) => sample.requests > 0 ?
    sample.errors_5xx / sample.requests : null);
  const falseBlockRate = samples.map((sample) => sample.honest_requests > 0 ?
    sample.wrongly_blocked / sample.honest_requests : null);
  const latency = samples.map((sample) => sample.requests > 0 ? sample.p95_ms : null);
  const errorReference = deployment.baseline_5xx > 0 ?
    Math.min(0.02, deployment.baseline_5xx * 3) : 0.02;
  return <section className="soc-deployment-observation" aria-label="Observação após implantação">
    <div className="soc-observation-heading"><h3>Observação após implantação</h3>
      <strong>{stateLabel[deployment.state] ?? "Estado desconhecido"}</strong></div>
    <p>Iniciada em {new Date(deployment.started_at).toLocaleString("pt-BR", {
      timeZone: "America/Sao_Paulo" })} · {samples.length} amostras{
        deployment.reason ? ` · motivo: ${reasonLabel[deployment.reason] ?? deployment.reason}` : ""}</p>
    <div className="soc-observation-charts">
      <MetricChart label="Erros HTTP 5xx" values={errorRate}
        format={(value) => `${(value * 100).toFixed(1)}%`} reference={errorReference}/>
      <MetricChart label="Latência p95" values={latency}
        format={(value) => `${Math.round(value)} ms`}
        reference={deployment.baseline_p95_ms * 3}/>
      <MetricChart label="Falso bloqueio" values={falseBlockRate}
        format={(value) => `${(value * 100).toFixed(2)}%`} reference={0.005}/>
    </div>
    <small>Linhas tracejadas: referências de alerta. O rollback considera janelas e outras verificações.
      Lacunas indicam ausência de tráfego na amostra.</small>
  </section>;
}
