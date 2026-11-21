import { newId } from "./id.ts";
import type { FastifyInstance } from "fastify";
import { Bank } from "./bank.ts";
import { withTrace } from "./telemetry.ts";
import { PUBLIC_TARIFF_SCHEDULE } from "./tariff-schedule.ts";
import { encodeResponseFieldEvidence } from "./response-field-evidence.ts";
export interface GatewayCall {
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: unknown;
    peerIp: string;
}
export interface GatewayResult {
    status: number;
    body: unknown;
    request_id: string;
}
const PUBLIC = new Set(["/api/v1/health", "/api/v1/openapi.json", "/api/v1/internal/ping", "/api/v1/tariffs"]);
const ALLOWED = [
    /^\/tariffs$/,
    /^\/onboarding\/apply$/,
    /^\/auth\/(login|logout|otp(?:\/verify)?|refresh(?:\/challenge)?|step-up|password)$/, /^\/auth\/devices\/[^/]+\/revoke$/,
    /^\/devices(?:\/[^/]+)?$/, /^\/devices\/current\/(?:pix-registration|key(?:\/challenge)?|operation-challenge|security-notices)$/,
    /^\/accounts$/, /^\/accounts\/payment$/, /^\/accounts\/[^/]+(?:\/(?:statement|close|salary-port|salary-portability))?$/, /^\/accounts\/limits\/recompute$/,
    /^\/accounts\/closed-credits(?:\/[^/]+\/claim)?$/,
    /^\/kyc\/(upgrade|documents|status)$/,
    /^\/customers\/me$/,
    /^\/pix\/(keys|transfers|med|scheduled)$/, /^\/pix\/keys\/[^/]+$/,
    /^\/pix\/keys\/[^/]+\/deregister$/,
    /^\/pix\/keys\/claims\/[^/]+(?:\/(?:verify|reissue|complete|close))?$/,
    /^\/pix\/limits\/night$/, /^\/pix\/limits\/channels\/[^/]+$/,
    /^\/pix\/med\/[^/]+$/,
    /^\/pix\/transfers\/[^/]+$/, /^\/pix\/scheduled\/[^/]+$/,
    /^\/pix\/scheduled\/[^/]+\/(cancel|reauthorize)$/,
    /^\/pix\/automatic\/offers(?:\/[^/]+(?:\/revoke)?)?$/,
    /^\/pix\/automatic\/mandates(?:\/[^/]+(?:\/(?:revoke|charges|migrate))?)?$/,
    /^\/pix\/automatic\/charges\/[^/]+\/(?:cancel|merchant-cancel|reauthorize|retry)$/,
    /^\/pix\/automatic\/notifications$/,
    /^\/incidents\/notices$/,
    /^\/pix\/automatic\/limits\/[^/]+$/,
    /^\/pix\/proximity\/(tokens|redeem)$/,
    /^\/psp\/notices(?:\/(?:login-challenge|login|operation-challenge|logout))?$/,
    /^\/risk\/(decisions|holds)$/,
    /^\/cards$/, /^\/cards\/[^/]+(?:\/(?:virtual|temporary|cvv))?$/,
    /^\/cards\/[^/]+\/wallet-tokens$/, /^\/cards\/wallet-tokens\/[^/]+\/revoke$/,
    /^\/cards\/[^/]+\/recurring$/, /^\/cards\/recurring\/[^/]+(?:\/(?:charges|revoke))?$/,
    /^\/cards\/credit\/[^/]+(?:\/statements(?:\/[^/]+(?:\/(?:pay|installment-plan))?)?)?$/,
    /^\/cards\/3ds\/challenges(?:\/[^/]+\/complete)?$/,
    /^\/cards\/network\/authorize$/,
    /^\/cards\/network\/wallet\/authorize$/,
    /^\/cards\/network\/[^/]+(?:\/dispute)?$/, /^\/cards\/disputes\/[^/]+$/,
    /^\/loans(?:\/(?:offers|quote)|\/[^/]+(?:\/contract|\/prepay|\/refinance|\/renegotiate|\/renegotiation-quote)?)?$/,
    /^\/loans\/[^/]+\/installments\/[1-9][0-9]*\/(?:pay|partial-pay)$/,
    /^\/data-sharing\/(consents(?:\/[^/]+\/revoke)?|read)$/,
];
const STATIC_ROUTE_PARTS = new Set([
    "api", "v0", "v1", "auth", "login", "logout", "otp", "verify", "refresh", "challenge",
    "step-up", "password", "devices", "revoke", "current", "pix-registration", "key",
    "operation-challenge", "security-notices", "accounts", "statement", "close", "limits",
    "recompute", "closed-credits", "claim", "payment", "salary-port", "salary-portability", "onboarding",
    "apply", "kyc", "upgrade", "documents", "status",
    "customers", "me", "pix", "keys", "lookup", "transfers", "med", "scheduled", "cancel",
    "channels", "app", "night",
    "reauthorize", "automatic", "offers", "mandates", "charges", "merchant-cancel", "retry", "migrate",
    "notifications", "proximity", "tokens", "redeem", "psp", "incidents", "notices", "risk", "decisions",
    "holds", "cards", "credit", "statements", "installment-plan", "3ds", "challenges",
    "complete", "virtual", "temporary", "cvv", "wallet", "wallet-tokens", "recurring", "network", "authorize", "dispute",
    "disputes", "loans", "quote", "contract", "installments", "pay", "partial-pay", "prepay", "refinance", "renegotiate", "renegotiation-quote",
    "data-sharing", "consents", "read", "tariffs",
]);
const TELEMETRY_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
export function gatewayRouteTemplate(pathname: string): string {
    if (PUBLIC.has(pathname))
        return pathname;
    if (pathname.startsWith("/api/v0/"))
        return "/api/v0/:path";
    if (!pathname.startsWith("/api/v1/"))
        return "/unmatched";
    const internal = pathname.slice("/api/v1".length);
    if (!isGatewayAllowed(internal))
        return "/api/v1/:unmatched";
    return `/api/v1${internal.split("/").map((part) => part && !STATIC_ROUTE_PARTS.has(part) ? ":id" : part).join("/")}`;
}
export function isGatewayAllowed(path: string): boolean {
    return ALLOWED.some((pattern) => pattern.test(path));
}
export class Gateway {
    readonly bank: Bank;
    readonly twin: FastifyInstance;
    private readonly windows = new Map<string, {
        started: number;
        count: number;
    }>();
    constructor(bank: Bank, twin: FastifyInstance) {
        this.bank = bank;
        this.twin = twin;
        bank.db.exec(`CREATE TABLE IF NOT EXISTS gateway_metrics (
      id INTEGER PRIMARY KEY, at TEXT NOT NULL, status INTEGER NOT NULL,
      duration_ms REAL NOT NULL
    );`);
    }
    // This checks the gateway telemetry write path, not the availability of the whole process.
    heartbeat(): void {
        this.bank.telemetry.emit({ source: "gateway", category: "health", action: "heartbeat",
            outcome: "success", message: "Gateway telemetry heartbeat" });
    }
    private hit(key: string, max: number, now = this.bank.now().getTime()): boolean {
        const existing = this.windows.get(key);
        if (!existing || now - existing.started >= 60000) {
            this.windows.set(key, { started: now, count: 1 });
            return true;
        }
        existing.count++;
        return existing.count <= max;
    }
    async call(input: GatewayCall): Promise<GatewayResult> {
        const requestId = newId("req", this.bank.realNow().getTime());
        return withTrace(requestId, () => this.execute(input, requestId), {
            sourceIp: input.peerIp,
            ...(input.headers?.["user-agent"] ? { userAgent: input.headers["user-agent"] } : {}),
        });
    }
    private async execute(input: GatewayCall, requestId: string): Promise<GatewayResult> {
        const started = performance.now();
        const method = input.method.toUpperCase();
        const url = new URL(input.path, "http://twin.local");
        const pathname = url.pathname;
        const reply = (status: number, body: unknown): GatewayResult => {
            this.bank.log({ actor: "gateway", kind: status === 429 ? "rate_limited" : "gateway_request",
                route: pathname, status, peerIp: input.peerIp });
            const route = gatewayRouteTemplate(pathname);
            const fields = encodeResponseFieldEvidence(method, route, status, body);
            this.bank.telemetry.emit({ source: "gateway", category: "request", action: "request",
                outcome: status < 400 ? "success" : "failure", severity: status >= 500 ? "error" :
                    status >= 400 ? "warn" : "info", sourceIp: input.peerIp,
                message: `Gateway ${TELEMETRY_METHODS.has(method) ? method : "OTHER"} ${route} completed` +
                    (fields === undefined ? "" : ` fields=${fields}`) });
            this.bank.db.prepare("INSERT INTO gateway_metrics (at,status,duration_ms) VALUES (?,?,?)")
                .run(this.bank.realNow().toISOString(), status, Math.max(0, performance.now() - started));
            return { status, body, request_id: requestId };
        };
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(input.peerIp))
            return reply(400, { error: "BIZ_INVALID_PEER" });
        const blocked = this.bank.db.prepare(`SELECT 1 FROM blue_containments WHERE kind='block_route'
      AND target=? AND lifted_at IS NULL AND expires_at>? LIMIT 1`)
            .get(`${method} ${pathname}`, this.bank.realNow().toISOString());
        if (blocked)
            return reply(503, { error: "DEF_BLOCKED" });
        if (input.body !== undefined && Buffer.byteLength(JSON.stringify(input.body), "utf8") > 32768)
            return reply(413, { error: "BIZ_BODY_TOO_LARGE" });
        const source = input.peerIp;
        if (!this.hit(`ip:${source}`, 300))
            return reply(429, { error: "BIZ_IP_RATE_LIMIT" });
        if (pathname.endsWith("/auth/login") && !this.hit(`login:${source}`, 10))
            return reply(429, { error: "BIZ_LOGIN_RATE_LIMIT" });
        if (pathname === "/api/v1/onboarding/apply" && method === "POST" &&
            !this.hit(`onboarding:${source}`, 3, this.bank.realNow().getTime()))
            return reply(429, { error: "BIZ_ONBOARDING_RATE_LIMIT" });
        const authorization = input.headers?.authorization;
        if (authorization && !this.hit(`session:${authorization}`, 120))
            return reply(429, { error: "BIZ_SESSION_RATE_LIMIT" });
        if (PUBLIC.has(pathname)) {
            if (method !== "GET")
                return reply(405, { error: "BIZ_METHOD_NOT_ALLOWED" });
            if (pathname === "/api/v1/health")
                return reply(200, { status: "ok" });
            if (pathname === "/api/v1/internal/ping")
                return reply(200, { status: "ok" });
            if (pathname === "/api/v1/tariffs")
                return reply(200, PUBLIC_TARIFF_SCHEDULE);
            return reply(200, { openapi: "3.1.0", info: { title: "Jacarandá Twin API", version: "1.0.0" }, paths: {} });
        }
        if (pathname.startsWith("/api/v0/")) {
            return reply(401, { error: "DEF_UNAUTHORIZED" });
        }
        if (!pathname.startsWith("/api/v1/"))
            return reply(404, { error: "DEF_NOT_FOUND" });
        const internal = pathname.slice("/api/v1".length);
        if (!isGatewayAllowed(internal))
            return reply(404, { error: "DEF_NOT_FOUND" });
        const response = await this.twin.inject({ method: method as "GET", url: `${internal}${url.search}`,
            headers: { ...(input.body === undefined ? {} : { "content-type": "application/json" }),
                ...(input.headers ?? {}), "x-twin-source-ip": input.peerIp },
            ...(input.body === undefined ? {} : { payload: JSON.stringify(input.body) }) });
        let body: unknown;
        try {
            body = response.json();
        }
        catch {
            body = { error: "INTERNAL_INVALID_RESPONSE" };
        }
        return reply(response.statusCode, body);
    }
}
