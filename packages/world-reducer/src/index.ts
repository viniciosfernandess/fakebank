import { AREAS, type Area, type ArenaEvent } from "../../contracts/src/index.ts";

export const REDUCER_VERSION = 6;
export type AreaState = "normal" | "probed" | "under_attack" | "breached" | "contained" | "patching" | "quarantined" | "hardened";
export interface WorldState {
  seq: number; round_id: string | null; round_no: number | null; round_status: string;
  area_states: Record<Area, AreaState>; scars: Record<Area, number>;
  agents: Record<string, { role: string; area?: Area; goal_pt: string; outcome?: string }>;
  sentinels: Record<Area, { state: string; alerts_24h: number; last_tick_s_ago: number;
    checks_total: number; last_tick_at: string | null }>;
  incidents: Record<string, { area: Area; severity: string; state: string; alert_count: number }>;
  features: Record<string, { area: Area; name_pt: string; day: number }>;
  flags: Record<string, boolean>;
  usage: { agents: number; turns: number; input_tokens: number; output_tokens: number;
    cached_input_tokens: number; wall_ms: number };
  score: { red: number; blue: number; collateral: number };
  health: { overall: number; areas: Record<Area, number> };
  honest_blocked: number; traffic_ops: number;
  traffic_by_area: Partial<Record<Area, number>> | null;
  risk_queue_pending: number | null; spi_reconciled: boolean | null;
  spi_available: boolean | null;
  twin_ts: string | null;
  captions: { seq: number; text: string; severity: string }[];
  rejections: number; rollbacks: number; restorations: number;
}

function areaRecord<T>(make: () => T): Record<Area, T> {
  return Object.fromEntries(AREAS.map((area) => [area, make()])) as Record<Area, T>;
}
export function initialWorld(): WorldState {
  return { seq: 0, round_id: null, round_no: null, round_status: "idle",
    area_states: areaRecord(() => "normal" as AreaState), scars: areaRecord(() => 0),
    agents: {}, sentinels: areaRecord(() => ({ state: "ok", alerts_24h: 0, last_tick_s_ago: 0,
      checks_total: 0, last_tick_at: null })),
    incidents: {}, features: {}, flags: {},
    usage: { agents: 0, turns: 0, input_tokens: 0, output_tokens: 0,
      cached_input_tokens: 0, wall_ms: 0 },
    score: { red: 0, blue: 0, collateral: 0 }, honest_blocked: 0, traffic_ops: 0,
    traffic_by_area: null, risk_queue_pending: null, spi_reconciled: null,
    spi_available: null,
    twin_ts: null,
    health: { overall: 100, areas: areaRecord(() => 100) },
    captions: [], rejections: 0, rollbacks: 0, restorations: 0 };
}

export function reduceWorld(previous: WorldState, event: ArenaEvent): WorldState {
  if (event.seq <= previous.seq) return previous;
  const state: WorldState = structuredClone(previous);
  state.seq = event.seq;
  state.twin_ts = event.twin_ts ?? state.twin_ts;
  const payload = event.public;
  const area = (event.area ?? payload.area) as Area | undefined;
  const setArea = (value: AreaState) => { if (area && AREAS.includes(area)) state.area_states[area] = value; };
  switch (event.type) {
    case "round.started":
      state.round_id = event.round_id; state.round_no = Number(payload.round_no); state.round_status = "live";
      state.agents = {}; state.honest_blocked = 0; state.rejections = 0; state.rollbacks = 0;
      state.restorations = 0; state.traffic_ops = 0; state.traffic_by_area = null;
      state.risk_queue_pending = null; state.spi_reconciled = null;
      state.spi_available = null;
      state.score = { red: 0, blue: 0, collateral: 0 };
      state.usage = { agents: 0, turns: 0, input_tokens: 0, output_tokens: 0,
        cached_input_tokens: 0, wall_ms: 0 };
      break;
    case "round.ended": state.round_status = String(payload.status); break;
    case "round.aborted": state.round_status = "aborted"; break;
    case "agent.spawned": state.agents[String(payload.agent_id)] = { role: String(payload.role), goal_pt: String(payload.goal_pt), ...(area ? { area } : {}) }; break;
    case "agent.finished": {
      const agent = state.agents[String(payload.agent_id)]; if (agent) agent.outcome = String(payload.outcome); break;
    }
    case "attack.attempted": setArea("under_attack"); break;
    case "attack.succeeded": setArea("breached"); break;
    case "attack.failed": setArea("normal"); break;
    case "sentinel.alert": {
      setArea(state.area_states[area!] === "normal" ? "probed" : state.area_states[area!]);
      if (area) state.sentinels[area].state = "alerting";
      break;
    }
    case "sentinel.status": if (area) state.sentinels[area] = { ...state.sentinels[area],
      state: String(payload.state), alerts_24h: Number(payload.alerts_24h),
      last_tick_s_ago: Number(payload.last_tick_s_ago), last_tick_at: event.ts }; break;
    case "incident.opened": if (area) state.incidents[String(payload.incident_id)] = { area, severity: String(payload.severity), state: "open", alert_count: Number(payload.alert_count) }; break;
    case "incident.updated": {
      const incident = state.incidents[String(payload.incident_id)]; if (incident) incident.state = String(payload.state); break;
    }
    case "containment.applied": setArea("contained"); state.honest_blocked += Number(payload.collateral_honest); break;
    case "task.opened": case "patch.proposed": setArea("patching"); break;
    case "review.rejected": state.rejections++; setArea("patching"); break;
    case "deploy.succeeded": setArea("hardened"); if (area) state.scars[area]++; break;
    case "deploy.rolled_back": setArea("breached"); state.rollbacks++; break;
    case "damage.restored": state.restorations++; break;
    case "area.quarantined": setArea("quarantined"); break;
    case "area.released": setArea("normal"); break;
    case "feature.launched": state.features[String(payload.feature_id)] = { area: area!, name_pt: String(payload.name_pt), day: Number(payload.day) }; break;
    case "flag.changed": state.flags[String(payload.key)] = Boolean(payload.enabled); break;
    case "sim.tick": {
      state.traffic_ops = Number(payload.ops); state.honest_blocked += Number(payload.honest_blocked);
      state.traffic_by_area = payload.by_area ?? null;
      state.risk_queue_pending = payload.risk_queue_pending === undefined ? null :
        Number(payload.risk_queue_pending);
      state.spi_reconciled = payload.spi_reconciled === undefined ? null :
        Boolean(payload.spi_reconciled);
      state.spi_available = payload.spi_available === undefined ? null :
        Boolean(payload.spi_available);
      if (payload.sentinels) {
        const areas = payload.sentinels as Record<Area, { state: string; checks_total: number; alerts_24h: number }>;
        for (const key of AREAS) state.sentinels[key] = { state: areas[key].state,
          checks_total: areas[key].checks_total, alerts_24h: areas[key].alerts_24h,
          last_tick_s_ago: 0, last_tick_at: event.ts };
      }
      break;
    }
    case "score.updated": if (event.round_id === state.round_id)
      state.score = { red: Number(payload.red), blue: Number(payload.blue),
        collateral: Number(payload.collateral ?? 0) }; break;
    case "health.updated": state.health = { overall: Number(payload.overall),
      areas: Object.fromEntries(AREAS.map((area) => [area,
        Number((payload.areas as Record<Area, number>)[area])])) as Record<Area, number> }; break;
    case "usage.updated": if (event.round_id === state.round_id) state.usage = {
      agents: Number(payload.agents), turns: Number(payload.turns),
      input_tokens: Number(payload.input_tokens), output_tokens: Number(payload.output_tokens),
      cached_input_tokens: Number(payload.cached_input_tokens), wall_ms: Number(payload.wall_ms) }; break;
    case "narration.published": state.captions.push({ seq: event.seq, text: String(payload.text_pt), severity: String(payload.severity) }); state.captions = state.captions.slice(-50); break;
  }
  return state;
}

export function replay(events: ArenaEvent[], start: WorldState = initialWorld()): WorldState {
  return events.reduce(reduceWorld, start);
}
export function shouldKeyframe(lastSeq: number, lastAtMs: number, event: ArenaEvent): boolean {
  return event.type === "round.started" || event.type === "round.ended" || event.seq - lastSeq >= 250 ||
    new Date(event.ts).getTime() - lastAtMs >= 10_000;
}
