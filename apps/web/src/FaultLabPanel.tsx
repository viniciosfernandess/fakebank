import { useEffect, useMemo, useState, type FormEvent } from "react";

type Domain = "security" | "fraud" | "operation" | "integrity";
interface Fixture { id: string; label: string; domain: Domain; description: string;
  available: boolean; incompatible_with: string[] }
interface Preview { compatible: boolean; reasons: string[]; selected: Fixture[];
  scope: { mode: "disposable_local"; max_faults: number; max_duration_ms: number } }
interface Run { id: string; status: string; selected_ids: string[];
  started_at: string; stopped_at: string | null; expires_at: string;
  timeline: { at: string; stage: string; fixture_id?: string; detail: string }[];
  results: { fixture_id: string; state: "pending" | "observed" | "not_observed";
    evidence_refs: string[] }[] }
type EvidenceState = "verified" | "pending" | "inconclusive" | "not_applicable";
type EvaluationVerdict = "pending" | "passed" | "inconclusive";
type EvaluationStageName = "symptom" | "detection" | "case" | "response" | "continuity" |
  "customer_repair" | "reconciliation" | "watch";
interface EvidenceStage { state: EvidenceState; reason: string; evidence_refs: string[] }
interface FixtureEvaluation extends Record<EvaluationStageName, EvidenceStage> {
  fixture_id: string;
  verdict: EvaluationVerdict;
}
interface FaultEvaluation { run_id: string; status: string; verdict: EvaluationVerdict;
  fixtures: FixtureEvaluation[] }
interface Session { authenticated: boolean; operator_id?: string; role?: string }
interface DefenseCase {
  incidentId: string;
  profile: "security" | "fraud" | "operations" | "integrity";
  area: string;
  severity: string;
  caseVersion: number;
  state: string;
  updatedAt: string;
  attentionReason: "impact_unverified" | "evidence_pending" |
    "technical_review" | null;
}
interface DefenseStatus {
  status: { total: number; awaitingRuntime: number; investigating: number;
    investigated: number; planning: number; planned: number;
    retryPending: number; needsAttention: number; lastError: string | null };
  cases: DefenseCase[];
}
interface DefenseCaseDetail {
  case: Pick<DefenseCase, "incidentId" | "profile" | "state">;
  timeline: { at: string; stage: string; detail: string; verified: boolean }[];
}
const RUN_KEY = "banco-vivo:fault-lab:current-run";
const domains: Domain[] = ["security", "fraud", "operation", "integrity"];
const domainNames: Record<Domain, string> = {
  security: "Segurança", fraud: "Fraude",
  operation: "Funcionamento", integrity: "Integridade financeira",
};
const stageNames: Record<string, string> = {
  armed: "Preparado", injection_started: "Falha iniciada",
  symptom_observed: "Sintoma observado", probe_completed: "Verificação concluída",
  probe_failed: "Verificação falhou", stopped: "Injeção parada",
  expired: "Prazo encerrado", failed: "Falha na execução",
  sentinel_alert: "Sentinela alertou", case_opened: "Caso aberto",
  correction_verified: "Correção verificada", repair_verified: "Reparo verificado",
  reconciled: "Conciliação verificada",
};
const statusNames: Record<string, string> = {
  arming: "Preparando", injecting: "Injetando", observed: "Sintoma observado",
  stopped: "Injeção parada", expired: "Prazo encerrado",
  failed: "Falhou", cleanup_failed: "Falha ao encerrar injeção",
};
const evaluationStages: { key: EvaluationStageName; label: string }[] = [
  { key: "symptom", label: "Sintoma" },
  { key: "detection", label: "Detecção" },
  { key: "case", label: "Caso vinculado" },
  { key: "response", label: "Resposta da defesa" },
  { key: "continuity", label: "Continuidade" },
  { key: "customer_repair", label: "Reparo ao cliente" },
  { key: "reconciliation", label: "Conciliação" },
  { key: "watch", label: "Observação após recuperação" },
];
const evidenceStateNames: Record<EvidenceState, string> = {
  verified: "Verificado", pending: "Pendente",
  inconclusive: "Inconclusivo", not_applicable: "Não aplicável",
};
const verdictNames: Record<EvaluationVerdict, string> = {
  pending: "Pendente", passed: "Aprovado com provas",
  inconclusive: "Inconclusivo",
};
const evaluationReasonNames: Record<string, string> = {
  symptom_not_proven: "O sintoma ainda não foi comprovado.",
  matching_sentinel_alert_missing: "Falta um alerta correspondente do Sentinela.",
  recovery_not_proven: "A retomada do serviço ainda não foi comprovada.",
  no_customer_loss_proven: "Não há prejuízo ao cliente comprovado neste caso.",
  no_financial_movement_proven: "Não há movimentação financeira comprovada neste caso.",
  source_gap_observed: "A interrupção da fonte foi observada.",
  exact_sentinel_emission: "A emissão do alerta do Sentinela ocorreu nesta execução.",
  auth_heartbeat_resumed: "O sinal da autenticação voltou.",
  gateway_heartbeat_resumed: "O sinal do gateway voltou.",
  run_owned_statement_unavailable: "A consulta de extrato do cliente falhou nesta execução.",
  customer_statement_access_not_restored: "O cliente ainda não conseguiu consultar o extrato.",
  statement_access_restored: "A consulta de extrato voltou a funcionar.",
  customer_statement_retry_succeeded: "O cliente conseguiu consultar o extrato após a falha.",
  run_owned_loan_offer_unavailable: "A consulta de oferta de crédito do cliente falhou nesta execução.",
  customer_loan_offer_access_not_restored: "O cliente ainda não conseguiu consultar a oferta de crédito.",
  loan_offer_access_restored: "A consulta de oferta de crédito voltou a funcionar.",
  customer_loan_offer_retry_succeeded: "O cliente conseguiu consultar a oferta de crédito após a falha.",
  run_owned_pix_automatic_mandates_unavailable: "A consulta de autorizações de Pix Automático falhou nesta execução.",
  customer_pix_automatic_mandates_access_not_restored: "O cliente ainda não conseguiu consultar suas autorizações de Pix Automático.",
  pix_automatic_mandates_access_restored: "A consulta de autorizações de Pix Automático voltou a funcionar.",
  customer_pix_automatic_mandates_retry_succeeded: "O cliente conseguiu consultar suas autorizações de Pix Automático após a falha.",
  run_owned_kyc_status_unavailable: "A consulta da verificação de identidade falhou nesta execução.",
  customer_kyc_status_access_not_restored: "O cliente ainda não conseguiu consultar sua verificação de identidade.",
  kyc_status_access_restored: "A consulta da verificação de identidade voltou a funcionar.",
  customer_kyc_status_retry_succeeded: "O cliente conseguiu consultar sua verificação de identidade após a falha.",
  run_owned_kyc_submission_unavailable: "O envio assinado da verificação de identidade falhou nesta execução.",
  customer_kyc_submission_access_not_restored: "O envio assinado ainda aguarda retomada.",
  kyc_submission_access_restored: "O envio da verificação de identidade voltou a funcionar.",
  customer_kyc_submission_retry_succeeded: "O pedido do cliente foi recebido para análise.",
  run_owned_kyc_review_interrupted: "A aprovação autenticada desta solicitação foi interrompida.",
  customer_kyc_review_pending: "O pedido continua pendente de revisão.",
  kyc_review_restored: "O revisor conseguiu retomar a análise deste pedido.",
  customer_kyc_review_completed: "O revisor aprovou a mesma solicitação pendente.",
  missing_hour_proof_published: "A prova da hora ausente foi publicada.",
  run_owned_risk_hold: "A retenção de risco pertence a esta execução.",
  hold_specific_policy_alert: "O alerta corresponde à retenção específica.",
  customer_transfer_not_verified: "A transferência ao cliente ainda não foi verificada.",
  transfer_ledger_not_verified: "O lançamento financeiro ainda não foi verificado.",
  held_payment_settled: "O pagamento retido foi liquidado.",
  verified_customer_transfer: "A transferência ao cliente foi verificada.",
  balanced_posting_and_bank_reconciliation: "Lançamentos balanceados e banco conciliado.",
  run_owned_payment_backlog: "A fila de pagamentos pertence a esta execução.",
  run_owned_med_opening_backlog: "A contestação desta execução aguardou confirmação do PSP.",
  med_opening_acknowledged: "O PSP confirmou a abertura da mesma contestação.",
  med_review_available: "A contestação entrou em análise.",
  med_opening_reconciliation_pending: "A abertura ou a conciliação da contestação ainda aguarda confirmação.",
  run_owned_med_analysis_backlog: "A análise desta contestação ficou pendente no DICT.",
  med_analysis_acknowledged: "O DICT confirmou a análise da mesma contestação.",
  med_analysis_available: "A contestação pode seguir para a próxima etapa.",
  med_analysis_reconciliation_pending: "A análise ou a conciliação da contestação ainda aguarda confirmação.",
  run_owned_med_completion_backlog: "O comando desta contestação ficou pendente no PSP.",
  med_settlement_acknowledged: "O PSP confirmou a liquidação da mesma contestação.",
  med_release_acknowledged: "O PSP confirmou a liberação das retenções.",
  med_original_payer_credited: "A restituição integral ao pagador original foi verificada.",
  med_holds_released_without_refund: "As retenções foram liberadas após a rejeição, sem reembolso.",
  med_completion_reconciliation_pending: "A confirmação do PSP ou a conciliação ainda está pendente.",
  run_owned_automatic_pix_backlog: "A cobrança autorizada desta execução ficou pendente após o vencimento.",
  automatic_pix_charge_settled: "A cobrança de Pix Automático foi liquidada.",
  automatic_pix_customer_posting_verified: "O débito e o crédito da cobrança foram verificados.",
  automatic_pix_settlement_pending: "A liquidação ou conciliação da cobrança ainda aguarda verificação.",
  payment_backlog_run_attribution_missing: "Falta vínculo entre a fila e esta execução.",
  transfer_specific_sentinel_link_missing: "Falta vínculo do alerta com esta transferência.",
  transfer_specific_sentinel_emission: "O alerta desta transferência foi emitido nesta execução.",
  payment_flow_resumed: "O fluxo do pagamento voltou.",
  customer_payment_completed: "O pagamento do cliente foi concluído.",
  customer_payment_pending: "O pagamento do cliente ainda está pendente.",
  cross_book_reconciliation_not_proven: "A conciliação entre livros não foi comprovada.",
  bank_and_external_books_reconciled: "Lançamentos do banco e livros externos conferidos após a falha.",
  run_owned_issuer_decline: "A recusa do emissor pertence a esta execução.",
  issuer_outage_decline_emission: "O alerta da recusa do emissor foi emitido nesta execução.",
  issuer_restored_and_authorization_accepted: "O emissor voltou e uma autorização foi aceita.",
  recipient_credit_acknowledged: "O crédito ao destinatário foi confirmado.",
  recipient_credit_not_proven: "O crédito ao destinatário ainda não foi comprovado.",
  decline_has_no_customer_debit: "A recusa não debitou o cliente.",
  decline_has_no_posting: "A recusa não gerou lançamento financeiro.",
  case_contains_exact_alert: "O caso contém o alerta exato.",
  matching_defense_case_missing: "Falta um caso da defesa vinculado ao alerta.",
  defense_case_version_missing: "Falta a versão do caso da defesa.",
  defense_investigation_missing: "Falta a investigação registrada para este caso.",
  defense_plan_or_approved_review_missing: "Falta plano ou revisão aprovada para este caso.",
  reviewed_code_candidate_not_applied: "A proposta de código foi revisada, mas não aplicada.",
  run_owned_rounding_drift: "A diferença contábil pertence a esta execução.",
  rounding_ledger_repair_not_proven: "A diferença contábil ainda não foi reparada.",
  corrected_code_running: "A correção aprovada está carregada no banco local.",
  no_customer_overcharge: "Os lançamentos mostram desconto ao cliente, sem cobrança excessiva.",
  bank_loss_booked_and_ledger_balanced: "A perda do banco foi registrada e o razão está conciliado.",
  reviewed_code_and_fee_repair: "A correção revisada e o reparo contábil foram comprovados.",
  code_or_fee_repair_unverified: "A aplicação da correção ou o reparo contábil ainda não foi comprovado.",
  reviewed_operational_action_applied: "A ação operacional revisada foi aplicada.",
  reviewed_operational_action_not_applied: "A ação operacional revisada ainda não foi aplicada.",
  reviewed_plan_has_no_verified_correction: "O plano revisado não comprova correção aplicada.",
  reviewed_external_recovery_receipt: "A recuperação externa foi comprovada por recibo vinculado ao caso e à revisão.",
  external_recovery_receipt_missing_or_mismatched: "Falta recibo de recuperação externa correspondente ao caso e à revisão.",
  individual_nonfinancial_harm_unknown: "O possível prejuízo individual pela recusa ainda não foi determinado.",
  known_service_harm_not_repaired: "Clientes com tentativas recusadas foram identificados; o reparo ainda não foi comprovado.",
  customer_notified_retry_unproven: "Clientes afetados receberam aviso; a conclusão das compras ainda não foi comprovada.",
  synthetic_revoked_device_record: "O laboratório apresentou um registro fictício de acesso após revogação.",
  run_owned_revoked_device_access: "Um aparelho revogado acessou a conta nesta execução.",
  access_impact_not_assessed: "O alcance do acesso ainda não foi avaliado.",
  access_impact_and_notice_unverified: "Faltam provas do impacto e do aviso ao cliente.",
  customer_notified_impact_unverified: "O cliente foi avisado; possíveis efeitos do acesso ainda não foram esclarecidos.",
  identity_replay_notice_and_scope_verified: "O cliente fictício foi avisado. A consulta simulada retornou uma lista vazia e não gerou lançamentos.",
  customer_notified_observed_scope_verified: "O cliente foi avisado e os campos retornados na janela registrada foram identificados. Os efeitos do acesso seguem em apuração.",
  no_identity_posting_in_observed_window: "A janela registrada e conciliada ficou sem lançamentos associados ao acesso.",
  identity_linked_posting_impact_unverified: "Foram encontrados lançamentos vinculados. O prejuízo e a autorização das operações seguem em apuração.",
  identity_pix_followup_impact_unverified: "O banco acompanha os Pix vinculados ao acesso, incluindo a resposta do SPI e o crédito no destino. O impacto ao cliente segue em apuração.",
  identity_pix_followup_evidence_pending: "A fila contém Pix vinculados. O caso aguarda o registro do estado atual.",
  revoked_device_sessions_closed: "As sessões do aparelho revogado foram encerradas.",
  reviewed_replay_identity_containment: "Parecer independente e bloqueio da sessão simulada verificados.",
  reviewed_code_and_identity_containment: "Correção revisada e contenção das sessões verificadas.",
  code_or_identity_containment_unverified: "Falta comprovar a correção ou o encerramento das sessões.",
  synthetic_missed_hold_record: "O laboratório apresentou um histórico fictício de Pix sem retenção.",
  run_owned_missed_fraud_hold: "Um Pix suspeito foi liquidado sem a retenção esperada nesta execução.",
  suspicious_payment_impact_unrepaired: "O efeito do Pix suspeito ainda não foi reparado.",
  suspicious_payment_impact_not_assessed: "O impacto do Pix suspeito ainda não foi avaliado.",
  suspicious_payment_impact_unverified: "A transferência foi identificada; autorização e prejuízo ainda não foram comprovados.",
  suspicious_payment_customer_notified_impact_unverified: "O cliente foi avisado e pode contestar o Pix; autorização e prejuízo ainda estão em apuração.",
  customer_dispute_recorded_repair_unverified: "O cliente contestou o Pix. A análise e a devolução ainda não foram comprovadas.",
  med_claim_rejected_impact_unresolved: "O MED recusou a contestação. O impacto do incidente ainda está em apuração.",
  med_partial_refund_remaining: "O cliente recebeu parte do valor. A reparação do restante segue pendente.",
  med_no_funds_recovered: "O MED foi concluído sem recuperar saldo. A reparação segue pendente.",
  approved_med_refund_verified: "Contestação aprovada e valor integral devolvido ao cliente, com crédito comprovado.",
  approved_med_compensation_verified: "O banco cobriu a diferença da contestação aprovada. O valor integral foi conciliado.",
  payment_and_med_refund_balanced: "Lançamentos do Pix e da devolução MED estão conciliados.",
  suspicious_payment_reconciliation_unverified: "Falta conciliar os lançamentos do Pix suspeito.",
  fraud_hold_policy_verified: "O banco confirmou que a retenção preventiva continua ativa.",
  fraud_hold_policy_restored: "A retenção antifraude voltou a funcionar.",
  reviewed_replay_pix_control: "Parecer independente e retenção preventiva verificados.",
  reviewed_code_and_fraud_control: "Correção revisada e controle antifraude verificados.",
  code_or_fraud_control_unverified: "Falta comprovar a correção ou a retomada do controle antifraude.",
  watch_waiting_for_normal_completion: "A execução ainda não terminou pelo prazo normal.",
  watch_waiting_for_recovery: "A correção e o reparo ainda não têm provas completas.",
  watch_clock_unavailable: "Não foi possível confirmar o horário da observação.",
  watch_window_open: "A observação de tráfego saudável ainda está em andamento.",
  watch_recurrence_observed: "O mesmo alerta reapareceu durante a observação.",
  watch_honest_traffic_unhealthy: "Houve bloqueio de cliente legítimo durante a observação.",
  watch_traffic_missing: "Faltam operações recentes suficientes para comprovar estabilidade.",
  watch_healthy_traffic_without_recurrence: "Operações recentes seguiram saudáveis, sem repetição do alerta.",
};
const defenseStateNames: Record<string, string> = {
  queued: "Na fila", awaiting_runtime: "Aguardando agente local",
  investigating: "Investigação em andamento", investigated: "Investigação proposta",
  planning: "Plano em elaboração", planned: "Plano proposto",
  reviewing: "Revisão em andamento", reviewed: "Revisão concluída",
  mitigated: "Contenção aplicada",
  retry_pending: "Nova tentativa pendente", needs_attention: "Requer atenção",
  code_candidate_ready: "Correção revisada pronta",
  code_merged: "Correção aplicada; reiniciando",
  customer_repaired: "Reparação verificada",
  monitoring_external: "Acompanhando dependência externa",
  external_recovered: "Recuperação externa verificada",
};
const defenseProfileNames: Record<DefenseCase["profile"], string> = {
  security: "Segurança", fraud: "Fraude", operations: "Operação",
  integrity: "Integridade",
};
const attentionReasonNames: Record<NonNullable<DefenseCase["attentionReason"]>, string> = {
  impact_unverified: "A correção está aplicada; falta comprovar o impacto e o reparo ao cliente.",
  evidence_pending: "A defesa aguarda evidência da recuperação ou da fonte observada.",
  technical_review: "A etapa técnica exige nova revisão ou evidência antes de avançar.",
};
const defenseStageNames: Record<string, string> = {
  "defense.observed": "Alerta do Sentinela",
  "defense.handoff": "Investigador despachado",
  "dossier.defense_investigation": "Investigação entregue",
  "defense.planning_handoff": "Plano e impacto despachados",
  "dossier.defense_impact": "Impacto avaliado",
  "dossier.defense_plan": "Plano proposto",
  "defense.planning_failure": "Plano ou impacto recusado",
  "defense.review_handoff": "Revisão iniciada",
  "dossier.defense_review": "Revisão concluída",
  "defense.mitigation_decision": "Decisão de defesa",
  "defense.external_monitoring": "Recuperação externa em observação",
  "defense.customer_notice": "Aviso individual registrado",
  "defense.external_recovery_verified": "Recuperação externa verificada",
  "defense.code_design": "Correção planejada",
  "defense.code_candidate": "Candidato passou no CI",
  "defense.code_review": "Código revisado",
  "defense.code_review_approved": "Correção aprovada",
  "defense.code_build_failure": "Implementação não passou nos testes",
  "defense.code_bank_gate": "Suíte completa aprovada",
  "defense.code_merged": "Correção aplicada no laboratório",
  "defense.identity_containment_verified": "Sessões do aparelho revogado encerradas",
  "defense.identity_activity_observed": "Atividade da sessão registrada",
  "defense.fraud_control_verified": "Controle antifraude restaurado",
  "defense.fee_repair_verified": "Reparação contábil verificada",
};
function defenseStageEvidence(stage: string, verified: boolean): string {
  if (stage === "defense.observed") return verified ?
    "Alerta registrado" : "Alerta sem confirmação";
  if (stage === "defense.mitigation_decision") return verified ?
    "Ação aplicada e verificada" : "Ação não aplicada";
  if (stage === "defense.external_monitoring")
    return "Em observação; sem prova de recuperação";
  if (stage === "defense.customer_notice") return verified ?
    "Aviso individual registrado no banco local; efeitos restantes seguem em apuração" :
    "Aviso individual sem prova";
  if (stage === "defense.external_recovery_verified") return verified ?
    "Emissor restaurado e autorização posterior comprovada; reparo individual pendente" :
    "Recuperação externa ainda sem prova";
  if (stage === "defense.code_candidate") return "Candidato testado; aguardando revisão";
  if (stage === "defense.code_review") return "Parecer do revisor independente";
  if (stage === "defense.code_merged") return "Aplicado somente na cópia isolada do laboratório";
  if (stage === "defense.fee_repair_verified")
    return "Perda contábil registrada uma vez; banco conciliado";
  if (stage === "defense.identity_containment_verified")
    return "Acesso futuro bloqueado; impacto anterior ainda exige apuração";
  if (stage === "defense.identity_activity_observed")
    return "Operações registradas para apuração do impacto";
  if (stage === "defense.fraud_control_verified")
    return "Nova falha bloqueada; efeito do Pix já liquidado ainda exige apuração";
  if (stage === "defense.planning_failure" ||
    stage === "defense.code_build_failure")
    return "Etapa recusada; o motivo fica registrado para a próxima tentativa";
  if (stage === "dossier.defense_review") return "Parecer, sem aplicação";
  if (stage.startsWith("dossier.")) return "Proposta, sem aplicação";
  return "Encaminhamento registrado";
}
function reasonName(value: string): string {
  if (value === "duplicate_fixture") return "A mesma falha foi selecionada duas vezes.";
  if (value === "empty_selection") return "Selecione pelo menos uma falha.";
  if (value === "too_many_fixtures") return "A seleção excede o máximo de falhas simultâneas.";
  if (value === "active_run_limit") return "Outra execução está ativa.";
  if (value.startsWith("unavailable:")) return "Uma falha selecionada está indisponível.";
  if (value.startsWith("incompatible:")) return "Há falhas incompatíveis na seleção.";
  return value;
}
const record = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value) ?
    value as Record<string, unknown> : null;
function parseFixture(value: unknown): Fixture {
  const row = record(value);
  if (!row || typeof row.id !== "string" || typeof row.label !== "string" ||
    typeof row.description !== "string" || typeof row.available !== "boolean" ||
    !domains.includes(row.domain as Domain) || !Array.isArray(row.incompatible_with) ||
    !row.incompatible_with.every((entry) => typeof entry === "string"))
    throw new Error("Catálogo de falhas inválido.");
  return row as unknown as Fixture;
}
function parseCatalog(value: unknown): Fixture[] {
  const rows = record(value)?.fixtures;
  if (!Array.isArray(rows)) throw new Error("Catálogo de falhas inválido.");
  return rows.map(parseFixture);
}
function parsePreview(value: unknown): Preview {
  const row = record(value);
  const scope = record(row?.scope);
  if (!row || typeof row.compatible !== "boolean" || !Array.isArray(row.reasons) ||
    !row.reasons.every((item) => typeof item === "string") ||
    !Array.isArray(row.selected) || !scope || scope.mode !== "disposable_local" ||
    typeof scope.max_faults !== "number" || typeof scope.max_duration_ms !== "number")
    throw new Error("Prévia do experimento inválida.");
  row.selected.forEach(parseFixture);
  return row as unknown as Preview;
}
function parseRun(value: unknown): Run {
  const row = record(record(value)?.run);
  if (!row || typeof row.id !== "string" || typeof row.status !== "string" ||
    !Array.isArray(row.selected_ids) || !row.selected_ids.every((id) => typeof id === "string") ||
    typeof row.started_at !== "string" ||
    !(row.stopped_at === null || typeof row.stopped_at === "string") ||
    typeof row.expires_at !== "string" || !Array.isArray(row.timeline) ||
    !Array.isArray(row.results)) throw new Error("Execução do laboratório inválida.");
  for (const item of row.timeline) {
    const event = record(item);
    if (!event || typeof event.at !== "string" || typeof event.stage !== "string" ||
      typeof event.detail !== "string" ||
      !(event.fixture_id === undefined || typeof event.fixture_id === "string"))
      throw new Error("Linha do tempo inválida.");
  }
  for (const item of row.results) {
    const result = record(item);
    if (!result || typeof result.fixture_id !== "string" ||
      !["pending", "observed", "not_observed"].includes(String(result.state)) ||
      !Array.isArray(result.evidence_refs) ||
      !result.evidence_refs.every((ref) => typeof ref === "string"))
      throw new Error("Resultado do experimento inválido.");
  }
  return row as unknown as Run;
}
function parseEvaluation(value: unknown, run: Run): FaultEvaluation {
  const row = record(value);
  const verdicts: EvaluationVerdict[] = ["pending", "passed", "inconclusive"];
  const states: EvidenceState[] = ["verified", "pending", "inconclusive", "not_applicable"];
  if (!row || row.run_id !== run.id || row.status !== run.status ||
    !verdicts.includes(row.verdict as EvaluationVerdict) ||
    !Array.isArray(row.fixtures) || row.fixtures.length !== run.selected_ids.length)
    throw new Error("Avaliação da defesa inválida.");
  const fixtureIds = new Set<string>();
  for (const item of row.fixtures) {
    const fixture = record(item);
    if (!fixture || typeof fixture.fixture_id !== "string" ||
      !run.selected_ids.includes(fixture.fixture_id) ||
      fixtureIds.has(fixture.fixture_id) ||
      !verdicts.includes(fixture.verdict as EvaluationVerdict))
      throw new Error("Avaliação de falha inválida.");
    fixtureIds.add(fixture.fixture_id);
    for (const { key } of evaluationStages) {
      const stage = record(fixture[key]);
      if (!stage || !states.includes(stage.state as EvidenceState) ||
        typeof stage.reason !== "string" || !stage.reason.trim() ||
        !Array.isArray(stage.evidence_refs) ||
        !stage.evidence_refs.every((ref) => typeof ref === "string" && ref.length > 0) ||
        (stage.state === "verified" && stage.evidence_refs.length === 0))
        throw new Error("Prova de avaliação inválida.");
    }
    if (fixture.verdict === "passed" &&
      (run.status !== "expired" ||
        ["symptom", "detection", "case", "response", "continuity"].some((key) =>
          record(fixture[key])?.state !== "verified") ||
        ["customer_repair", "reconciliation"].some((key) =>
          !["verified", "not_applicable"].includes(
            String(record(fixture[key])?.state))) ||
        record(fixture.watch)?.state !== "verified"))
      throw new Error("Aprovação sem provas completas.");
  }
  if (row.verdict === "passed" &&
    row.fixtures.some((item) => record(item)?.verdict !== "passed"))
    throw new Error("Aprovação sem provas completas.");
  return row as unknown as FaultEvaluation;
}
function parseDefenseStatus(value: unknown): DefenseStatus {
  const row = record(value);
  const status = record(row?.status);
  if (!row || !status || !Array.isArray(row.cases) ||
    typeof status.total !== "number" ||
    !(status.lastError === null || typeof status.lastError === "string"))
    throw new Error("Estado da defesa inválido.");
  for (const item of row.cases) {
    const current = record(item);
    if (!current || typeof current.incidentId !== "string" ||
      typeof current.profile !== "string" || typeof current.area !== "string" ||
      typeof current.severity !== "string" || typeof current.caseVersion !== "number" ||
      typeof current.state !== "string" || typeof current.updatedAt !== "string" ||
      ![null, "impact_unverified", "evidence_pending", "technical_review"]
        .includes(current.attentionReason as string | null))
      throw new Error("Caso da defesa inválido.");
  }
  return row as unknown as DefenseStatus;
}
function parseDefenseCaseDetail(value: unknown): DefenseCaseDetail {
  const row = record(value);
  const item = record(row?.case);
  if (!row || !item || typeof item.incidentId !== "string" ||
    typeof item.profile !== "string" || typeof item.state !== "string" ||
    !Array.isArray(row.timeline)) throw new Error("Detalhe do caso inválido.");
  for (const entry of row.timeline) {
    const event = record(entry);
    if (!event || typeof event.at !== "string" ||
      typeof event.stage !== "string" || typeof event.detail !== "string" ||
      typeof event.verified !== "boolean")
      throw new Error("Histórico do caso inválido.");
  }
  return row as unknown as DefenseCaseDetail;
}
async function api(path: string, method: "GET" | "POST" = "GET", body?: object,
  signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(path, { method, cache: "no-store",
    credentials: "same-origin", ...(signal ? { signal } : {}),
    ...(body ? { headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body) } : {}) });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403)
      throw new Error("Entre como operador autorizado para usar o laboratório local.");
    if (response.status === 404) throw new Error("Laboratório indisponível nesta execução.");
    if (response.status === 409) throw new Error("Seleção incompatível ou execução em andamento.");
    throw new Error("Falha na comunicação com o laboratório local.");
  }
  return response.json() as Promise<unknown>;
}
const at = (iso: string) => {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString("pt-BR",
    { hour: "2-digit", minute: "2-digit", second: "2-digit" });
};
function rememberedRun(): string | null {
  try {
    const id = sessionStorage.getItem(RUN_KEY);
    return id && /^[a-zA-Z0-9_-]{1,128}$/.test(id) ? id : null;
  } catch { return null; }
}

export function FaultLabPanel({ enabled, presentation }: {
  enabled: boolean; presentation: boolean;
}) {
  const [session, setSession] = useState<Session | null>(null);
  const [operatorId, setOperatorId] = useState("");
  const [password, setPassword] = useState("");
  const [fixtures, setFixtures] = useState<Fixture[] | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [selectionPreview, setSelectionPreview] = useState<Preview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [runId, setRunId] = useState<string | null>(rememberedRun);
  const [activeRun, setActiveRun] = useState<Run | null>(null);
  const [evaluation, setEvaluation] = useState<FaultEvaluation | null>(null);
  const [evaluationError, setEvaluationError] = useState<string | null>(null);
  const [defense, setDefense] = useState<DefenseStatus | null>(null);
  const [defenseError, setDefenseError] = useState<string | null>(null);
  const [expandedCaseId, setExpandedCaseId] = useState<string | null>(null);
  const [caseDetail, setCaseDetail] = useState<DefenseCaseDetail | null>(null);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [caseLoading, setCaseLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    void Promise.all([
      api("/api/fault-lab/catalog", "GET", undefined, controller.signal),
      fetch("/api/operator/session", { cache: "no-store", signal: controller.signal })
        .then((response) => response.ok ? response.json() as Promise<Session> :
          { authenticated: false }),
    ]).then(([catalogValue, identity]) => {
      if (controller.signal.aborted) return;
      setFixtures(parseCatalog(catalogValue));
      setSession(identity.authenticated ? identity : { authenticated: false });
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message :
        "Catálogo indisponível.");
    });
    return () => controller.abort();
  }, [enabled]);
  useEffect(() => {
    if (!enabled || presentation || !session?.authenticated) return;
    const controller = new AbortController();
    let pending = false;
    const refresh = () => {
      if (pending) return;
      pending = true;
      void api("/api/fault-lab/catalog", "GET", undefined, controller.signal)
        .then((value) => {
          if (!controller.signal.aborted) setFixtures(parseCatalog(value));
        }).catch(() => { /* Keep the last catalog during a transient read failure. */ })
        .finally(() => { pending = false; });
    };
    refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [enabled, presentation, session?.authenticated]);
  useEffect(() => {
    if (!enabled || !expandedCaseId) return;
    const controller = new AbortController();
    setCaseLoading(true);
    const refresh = () => { void api(
      `/api/defense/cases/${encodeURIComponent(expandedCaseId)}`, "GET", undefined,
      controller.signal).then((value) => {
        if (!controller.signal.aborted) {
          const detail = parseDefenseCaseDetail(value);
          if (detail.case.incidentId !== expandedCaseId)
            throw new Error("Identificador do caso divergente.");
          setCaseDetail(detail); setCaseError(null);
        }
      }).catch((cause: unknown) => { if (!controller.signal.aborted)
        setCaseError(cause instanceof Error ? cause.message : "Detalhe indisponível.");
      }).finally(() => { if (!controller.signal.aborted) setCaseLoading(false); }); };
    refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [enabled, expandedCaseId]);

  useEffect(() => {
    if (!enabled || !session?.authenticated ||
      !["admin", "reviewer"].includes(session.role ?? "") || selected.length === 0) {
      setSelectionPreview(null); setPreviewing(false); return;
    }
    const controller = new AbortController();
    setPreviewing(true);
    const timer = window.setTimeout(() => {
      void api("/api/fault-lab/preview", "POST", { ids: selected }, controller.signal)
        .then((value) => { if (!controller.signal.aborted) {
          setSelectionPreview(parsePreview(value)); setError(null);
        } }).catch((cause: unknown) => { if (!controller.signal.aborted) {
          setSelectionPreview(null);
          setError(cause instanceof Error ? cause.message : "Prévia indisponível.");
        } }).finally(() => { if (!controller.signal.aborted) setPreviewing(false); });
    }, 150);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [enabled, session?.authenticated, selected]);

  useEffect(() => {
    if (!enabled || !session?.authenticated || !runId) return;
    const controller = new AbortController();
    const refresh = () => { void api(`/api/fault-lab/runs/${encodeURIComponent(runId)}`,
      "GET", undefined, controller.signal).then((value) => {
        if (!controller.signal.aborted) {
          const next = parseRun(value);
          const assessed = parseEvaluation(record(value)?.evaluation, next);
          setActiveRun(next); setEvaluation(assessed); setEvaluationError(null);
        }
      }).catch((cause: unknown) => { if (!controller.signal.aborted) {
        setEvaluation(null);
        setEvaluationError(cause instanceof Error ? cause.message :
          "Avaliação indisponível.");
      } }); };
    refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [enabled, session?.authenticated, runId]);
  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    const refresh = () => { void api("/api/defense/status", "GET", undefined,
      controller.signal).then((value) => {
        if (!controller.signal.aborted) {
          setDefense(parseDefenseStatus(value));
          setDefenseError(null);
        }
      }).catch((cause: unknown) => { if (!controller.signal.aborted)
        setDefenseError(cause instanceof Error ? cause.message : "Defesa indisponível."); }); };
    refresh();
    const timer = window.setInterval(refresh, 2000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [enabled]);

  const labels = useMemo(() => new Map(fixtures?.map((item) =>
    [item.id, item.label]) ?? []), [fixtures]);
  const terminal = activeRun && ["stopped", "expired", "failed", "passed", "aborted", "inconclusive"]
    .includes(activeRun.status);
  const authorized = session?.authenticated &&
    (session.role === "admin" || session.role === "reviewer");
  const canStart = !presentation && authorized && !busy && !previewing &&
    selectionPreview?.compatible === true && selected.length > 0 &&
    selected.every((id) => fixtures?.some((item) => item.id === id && item.available)) &&
    (!activeRun || terminal);
  const canStop = !presentation && authorized && !busy && activeRun && !terminal &&
    activeRun.stopped_at === null;

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const secret = password;
    setPassword(""); setBusy(true); setError(null);
    try {
      const identity = await api("/api/operator/login", "POST",
        { id: operatorId, password: secret }) as Session;
      if (!identity.authenticated) throw new Error("Acesso negado.");
      setSession(identity);
      window.dispatchEvent(new Event("bv-operator-session"));
    } catch { setError("Acesso negado. Confira credenciais e papel do operador."); }
    finally { setBusy(false); }
  }
  async function start() {
    if (!canStart) return;
    setBusy(true); setError(null);
    try {
      const next = parseRun(await api("/api/fault-lab/runs", "POST", { ids: selected }));
      setActiveRun(next); setEvaluation(null); setEvaluationError(null); setRunId(next.id);
      try { sessionStorage.setItem(RUN_KEY, next.id); } catch { /* In-memory state still works. */ }
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Falha ao iniciar."); }
    finally { setBusy(false); }
  }
  async function logout() {
    setBusy(true); setError(null);
    try {
      await api("/api/operator/logout", "POST");
      setSession({ authenticated: false }); setSelectionPreview(null);
      window.dispatchEvent(new Event("bv-operator-session"));
    } catch { setError("Não foi possível sair da sessão."); }
    finally { setBusy(false); }
  }
  async function stop() {
    if (!canStop || !activeRun) return;
    setBusy(true); setError(null);
    try { setActiveRun(parseRun(await api(
      `/api/fault-lab/runs/${encodeURIComponent(activeRun.id)}/stop`, "POST")));
      setEvaluation(null); setEvaluationError(null); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Falha ao parar."); }
    finally { setBusy(false); }
  }

  return <main className="fault-lab-page">
    <header className="fault-lab-heading"><small>LOCALHOST · BANCO DESCARTÁVEL</small>
      <h1>Laboratório de falhas</h1>
      <p>Escolha o que falhar. A defesa só recebe os efeitos observáveis, sem o gabarito do experimento.</p>
      {presentation && <p>Modo apresentação: controles de execução indisponíveis.</p>}
    </header>
    {!enabled ? <p className="fault-lab-note">Inicie o modo local do laboratório para usar esta página.</p> : <>
      {error && <p className="fault-lab-error" role="alert">{error}</p>}
      {session && !session.authenticated && !presentation && <section className="fault-lab-section">
        <h2>Entrar como operador</h2>
        <p className="fault-lab-note">O laboratório exige uma conta local de operador. Se ainda não existe, crie com <code>pnpm operator bootstrap &lt;id&gt;</code>.</p>
        <form className="fault-lab-login" onSubmit={(event) => { void login(event); }}>
          <label>Identificador<input required autoComplete="username" value={operatorId}
            onChange={(event) => setOperatorId(event.target.value)}/></label>
          <label>Senha<input required type="password" autoComplete="current-password"
            value={password} onChange={(event) => setPassword(event.target.value)}/></label>
          <button type="submit" disabled={busy}>Entrar</button>
        </form>
      </section>}
      {session?.authenticated && !presentation && <div className="fault-lab-session">
        <span>Operador {session.operator_id ?? "local"} · {session.role ?? "papel desconhecido"}</span>
        <button type="button" onClick={() => { void logout(); }} disabled={busy}>Trocar operador</button>
        {!authorized && <p role="alert">Entre com uma conta de administrador ou revisor para executar falhas.</p>}
      </div>}
      <section className="fault-lab-section" aria-labelledby="fault-lab-catalog">
        <div className="fault-lab-section-heading"><h2 id="fault-lab-catalog">1 · Selecionar</h2>
          <span>{selected.length} falha{selected.length === 1 ? "" : "s"}</span></div>
        {!fixtures ? <p className="fault-lab-note">Carregando catálogo…</p> :
          <div className="fault-lab-catalog">{domains.map((domain) => {
            const rows = fixtures.filter((item) => item.domain === domain);
            return rows.length ? <fieldset key={domain} className="fault-lab-group">
              <legend>{domainNames[domain]}</legend>
              {rows.map((item) => <label key={item.id} className="fault-lab-choice">
                <input type="checkbox" checked={selected.includes(item.id)}
                  disabled={(!item.available && !selected.includes(item.id)) ||
                    presentation || busy || !authorized}
                  onChange={(event) => {
                    setSelectionPreview(null);
                    setSelected((current) => event.target.checked ?
                      [...current, item.id] : current.filter((id) => id !== item.id));
                  }}/>
                <span><strong>{item.label}</strong><small>{item.description}</small>
                  {!item.available && <small>Indisponível nesta execução</small>}</span>
              </label>)}</fieldset> : null;
          })}</div>}
      </section>
      <section className="fault-lab-section" aria-labelledby="fault-lab-preview">
        <div className="fault-lab-section-heading"><h2 id="fault-lab-preview">2 · Conferir alcance</h2></div>
        {selected.length === 0 ? <p className="fault-lab-note">Selecione uma ou mais falhas.</p> :
          previewing ? <p className="fault-lab-note">Verificando combinação e limites…</p> :
            !selectionPreview ? <p className="fault-lab-note">Prévia indisponível; início bloqueado.</p> :
              <div className="fault-lab-preview">
                <strong className={selectionPreview.compatible ? "fault-lab-ok" : "fault-lab-warning"}>
                  {selectionPreview.compatible ? "Combinação permitida" : "Combinação incompatível"}</strong>
                <p>{selectionPreview.selected.map((item) => item.label).join(" · ")}</p>
                <small>Somente banco local descartável · máximo de {selectionPreview.scope.max_faults} falhas
                  {" · "}até {Math.ceil(selectionPreview.scope.max_duration_ms / 1000)} segundos</small>
                {selectionPreview.reasons.length > 0 && <ul>{selectionPreview.reasons.map((reason) =>
                  <li key={reason}>{reasonName(reason)}</li>)}</ul>}
              </div>}
        <div className="fault-lab-actions">
          <button type="button" disabled={!canStart} onClick={() => { void start(); }}>
            {busy ? "Aguarde…" : "Iniciar falhas selecionadas"}</button>
          {activeRun && <button type="button" disabled={!canStop} onClick={() => { void stop(); }}>
            Parar injeção</button>}
        </div>
      </section>
      <section className="fault-lab-section" aria-labelledby="fault-lab-run">
        <div className="fault-lab-section-heading"><h2 id="fault-lab-run">3 · Observar</h2>
          {activeRun && <span>{statusNames[activeRun.status] ?? activeRun.status}</span>}</div>
        {!activeRun ? <p className="fault-lab-note">Nenhuma execução carregada nesta sessão.</p> : <>
          <p className="fault-lab-run-meta">Execução {activeRun.id} · iniciada às {at(activeRun.started_at)}
            {activeRun.stopped_at && <> · injeção parada às {at(activeRun.stopped_at)}</>}</p>
          <div className="fault-lab-results">{activeRun.results.map((result) =>
            <article key={result.fixture_id}><strong>{labels.get(result.fixture_id) ?? result.fixture_id}</strong>
              <span>{result.state === "observed" ? "Sintoma observado" :
                result.state === "not_observed" ? "Sintoma não observado" : "Aguardando sintoma"}</span>
              {result.evidence_refs.length > 0 &&
                <small>Provas: {result.evidence_refs.join(" · ")}</small>}</article>)}</div>
          <div className="fault-lab-evaluation">
            <div className="fault-lab-section-heading"><h3>Avaliação da defesa</h3>
              {evaluation?.run_id === activeRun.id &&
                <span className={`fault-lab-evaluation-${evaluation.verdict}`}>
                  {verdictNames[evaluation.verdict]}</span>}</div>
            {evaluationError && <p className="fault-lab-warning" role="alert">
              Avaliação indisponível: {evaluationError}</p>}
            {!evaluation && !evaluationError && <p className="fault-lab-note">
              Aguardando avaliação baseada em provas…</p>}
            {evaluation?.run_id === activeRun.id && evaluation.fixtures.map((fixture) =>
              <article key={fixture.fixture_id} className="fault-lab-evaluation-fixture">
                <div className="fault-lab-evaluation-heading">
                  <strong>{labels.get(fixture.fixture_id) ?? fixture.fixture_id}</strong>
                  <span className={`fault-lab-evaluation-${fixture.verdict}`}>
                    {verdictNames[fixture.verdict]}</span>
                </div>
                <ol>{evaluationStages.map(({ key, label }) => {
                  const stage = fixture[key];
                  return <li key={key}>
                    <strong>{label}</strong>
                    <span className={`fault-lab-evidence-${stage.state}`}>
                      {evidenceStateNames[stage.state]}</span>
                    <small>{evaluationReasonNames[stage.reason] ?? stage.reason}</small>
                    {stage.evidence_refs.length > 0 &&
                      <small>Provas: {stage.evidence_refs.join(" · ")}</small>}
                  </li>;
                })}</ol>
              </article>)}
            <p className="fault-lab-note">Injeção e sintoma sozinhos não aprovam a defesa. A aprovação exige detecção, caso vinculado, resposta aplicada ou recuperação externa revisada, continuidade, reparo/conciliação quando aplicáveis e uma janela posterior de tráfego saudável.</p>
          </div>
          <ol className="fault-lab-timeline" aria-label="Linha do tempo observada">{activeRun.timeline.map(
            (item, index) => <li key={`${item.at}-${item.stage}-${index}`}>
              <time dateTime={item.at}>{at(item.at)}</time>
              <span><strong>{stageNames[item.stage] ?? item.stage.replaceAll("_", " ")}</strong>
                {item.fixture_id && <> · {labels.get(item.fixture_id) ?? item.fixture_id}</>}
                <small>{item.detail}</small></span>
            </li>)}</ol>
          {activeRun.timeline.length === 0 && <p className="fault-lab-note">Aguardando fatos observados.</p>}
          <p className="fault-lab-note">“Sintoma observado” comprova a falha, não a defesa. A defesa exige provas próprias de detecção, correção, reparo e conciliação.</p>
        </>}
      </section>
      <section className="fault-lab-section" aria-labelledby="fault-lab-defense">
        <div className="fault-lab-section-heading"><h2 id="fault-lab-defense">4 · Defesa real</h2>
          {defense && <span>{defense.status.total} caso{defense.status.total === 1 ? "" : "s"}</span>}
        </div>
        {defenseError && <p className="fault-lab-warning" role="alert">{defenseError}</p>}
        {!defense ? <p className="fault-lab-note">Aguardando estado da defesa local…</p> :
          <>
            {defense.status.lastError && <p className="fault-lab-warning" role="alert">
              Coordenador: {defense.status.lastError}</p>}
            {defense.cases.length === 0 ? <p className="fault-lab-note">
              Nenhum caso aberto pela defesa até agora.</p> :
              <ol className="fault-lab-defense-cases">{defense.cases.map((item) =>
                <li key={item.incidentId}>
                  <div><strong>{defenseProfileNames[item.profile] ?? item.profile}</strong>
                    <span>{defenseStateNames[item.state] ?? item.state}</span></div>
                  <small>Caso {item.incidentId} · {item.area} · gravidade {item.severity}
                    {" · "}versão {item.caseVersion} · atualizado às {at(item.updatedAt)}</small>
                  {item.attentionReason && <small className="fault-lab-warning">
                    {attentionReasonNames[item.attentionReason]}</small>}
                  <button type="button" aria-expanded={expandedCaseId === item.incidentId}
                    onClick={() => {
                      setExpandedCaseId((current) => current === item.incidentId ? null : item.incidentId);
                      setCaseDetail(null); setCaseError(null);
                    }}>{expandedCaseId === item.incidentId ? "Ocultar histórico" : "Ver histórico real"}</button>
                  {expandedCaseId === item.incidentId && <div className="fault-lab-case-detail">
                    {caseError && <p className="fault-lab-warning" role="alert">{caseError}</p>}
                    {!caseDetail && caseLoading && <p className="fault-lab-note">Carregando histórico…</p>}
                    {caseDetail?.case.incidentId === item.incidentId &&
                      (caseDetail.timeline.length === 0 ? <p className="fault-lab-note">
                        Nenhuma etapa registrada para este caso.</p> :
                        <ol className="fault-lab-timeline" aria-label={`Histórico do caso ${item.incidentId}`}>
                          {caseDetail.timeline.map((entry, index) => <li
                            key={`${entry.at}-${entry.stage}-${index}`}>
                            <time dateTime={entry.at}>{at(entry.at)}</time>
                            <span><strong>{defenseStageNames[entry.stage] ?? entry.stage}</strong>
                              <small>{entry.detail}</small>
                              <small>{defenseStageEvidence(entry.stage, entry.verified)}</small>
                            </span>
                          </li>)}</ol>)}
                  </div>}
                </li>)}</ol>}
            <p className="fault-lab-note">Investigação, plano e parecer não aplicam correções. O histórico distingue ações aplicadas e verificadas de ações adiadas; só uma etapa com prova própria comprova reparo. O vínculo de cada caso com a falha selecionada também exige evidência.</p>
          </>}
      </section>
    </>}
  </main>;
}
