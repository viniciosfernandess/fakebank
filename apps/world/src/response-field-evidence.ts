type FieldType = "number" | "string" | "nullable_string" | "array";

interface ChildProjection {
  required: Readonly<Record<string, FieldType>>;
  optional?: Readonly<Record<string, FieldType>>;
}

interface ResponseProjection {
  fields: Readonly<Record<string, FieldType>>;
  categoryPt: string;
  collection?: true;
  children?: Readonly<Record<string, ChildProjection>>;
}

const pixFields = {
  id: "string", end_to_end_id: "nullable_string", from_account: "string", to_account: "string",
  amount: "number", status: "string", initiated_at: "string", settled_at: "nullable_string",
} as const;

const projections: Readonly<Record<string, ResponseProjection>> = {
  "/api/v1/customers/me": { categoryPt: "dados de contato",
    fields: { email: "nullable_string", phone: "nullable_string" } },
  "/api/v1/kyc/status": { categoryPt: "situação da verificação de identidade",
    fields: { tier: "number", status: "string" } },
  "/api/v1/accounts/:id": { categoryPt: "resumo da conta", fields: {
    id: "string", kind: "string", ispb: "string", branch_code: "nullable_string",
    account_number: "nullable_string", account_digit: "nullable_string",
    balance_cents: "number", available_balance_cents: "number",
    overdraft_limit_cents: "number", daily_pix_limit_cents: "number", status: "string",
  } },
  "/api/v1/accounts": { categoryPt: "lista de contas", collection: true, fields: {
    id: "string", kind: "string", balance_cached: "number", status: "string",
    branch_code: "nullable_string", account_number: "nullable_string",
    account_digit: "nullable_string", ispb: "string", available_balance_cents: "number",
  } },
  "/api/v1/accounts/:id/statement": { categoryPt: "lançamentos do extrato", collection: true,
    fields: { tx_id: "string", amount: "number", kind: "string", created_at: "string" } },
  "/api/v1/devices": { categoryPt: "lista de aparelhos", collection: true, fields: {
    id: "string", first_seen_at: "string", trusted_at: "nullable_string",
    revoked_at: "nullable_string", pix_registered_at: "nullable_string",
  } },
  "/api/v1/pix/transfers": { categoryPt: "histórico de Pix enviados", collection: true, fields: {
    ...pixFields,
    med_case_id: "nullable_string", med_status: "nullable_string", psp_credit_status: "nullable_string",
  } },
  "/api/v1/pix/transfers/:id": { categoryPt: "detalhes de uma transferência Pix",
    fields: { ...pixFields, psp_credit_status: "nullable_string",
      status_history: "array", spi_messages: "array", returns: "array" },
    children: {
      status_history: { required: { status: "string", changed_at: "string", reason: "nullable_string" } },
      spi_messages: { required: { type: "string", end_to_end_id: "string",
        from_ispb: "string", to_ispb: "string", amount_cents: "number" },
        optional: { sender_account: "string", recipient_account: "string",
          root_transfer_id: "string", deadline_at_real: "string", status: "string",
          reason: "string", return_id: "string" } },
      returns: { required: { id: "string", amount: "number", reason: "string",
        status: "string", created_at: "string" } },
    },
  },
  "/api/v1/cards": { categoryPt: "lista de cartões", collection: true, fields: {
    id: "string", customer_id: "string", account_id: "string", parent_id: "nullable_string",
    kind: "string", status: "string", online_enabled: "number", international_enabled: "number",
    limit_cents: "number", used_cents: "number", expires_at: "nullable_string",
    effective_limit_cents: "number", last4: "string",
  } },
  "/api/v1/cards/:id/cvv": { categoryPt: "código de segurança de um cartão virtual",
    fields: { cvv: "string", expires_at: "string" } },
  "/api/v1/loans/offers": { categoryPt: "condições de uma oferta de crédito",
    fields: { id: "string", customer_id: "string", max_amount_cents: "number",
      rate_bps_month: "number", expires_at: "string", accepted_at: "nullable_string" } },
};

function projectionFor(route: string): ResponseProjection | undefined {
  return Object.hasOwn(projections, route) ? projections[route] : undefined;
}

function matchesField(value: unknown, type: FieldType): boolean {
  if (type === "array") return Array.isArray(value);
  if (type === "nullable_string") return value === null || typeof value === "string";
  return typeof value === type;
}

function nestedFields(parent: string, rows: unknown[], projection: ChildProjection): string[] {
  const required = Object.entries(projection.required);
  const shape = { ...projection.required, ...projection.optional };
  const present = new Set<string>();
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return [];
    const values = row as Record<string, unknown>;
    if (required.some(([key]) => !Object.hasOwn(values, key))) return [];
    for (const [key, value] of Object.entries(values)) {
      if (!Object.hasOwn(shape, key) || !matchesField(value, shape[key]!)) return [];
      if (value !== null) present.add(`${parent}.${key}`);
    }
  }
  return [...present];
}

function fieldNames(projection: ResponseProjection): string[] {
  return Object.keys(projection.fields).flatMap((key) => {
    const child = projection.children?.[key];
    return child ? [key, ...Object.keys({ ...child.required, ...child.optional })
      .map((field) => `${key}.${field}`)] : [key];
  });
}

export function encodeResponseFieldEvidence(method: string, route: string, status: number,
  body: unknown): string | undefined {
  const projection = projectionFor(route);
  if (method !== "GET" || !projection || status !== 200 ||
    Array.isArray(body) !== Boolean(projection.collection)) return undefined;
  const rows = Array.isArray(body) ? body as unknown[] : [body];
  const fields = Object.entries(projection.fields);
  const present = new Set<string>();
  for (const row of rows) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return undefined;
    const values = row as Record<string, unknown>;
    if (Object.keys(values).length !== fields.length || fields.some(([key, type]) =>
      !Object.hasOwn(values, key) || !matchesField(values[key], type)))
      return undefined;
    for (const [key] of fields) {
      const value = values[key];
      if (value !== null && (!Array.isArray(value) || value.length > 0)) present.add(key);
      const child = projection.children?.[key];
      if (child && Array.isArray(value))
        for (const name of nestedFields(key, value, child)) present.add(name);
    }
  }
  return fieldNames(projection).filter((name) => present.has(name)).join(",") || "none";
}

export function decodeResponseFieldEvidence(method: string, route: string, outcome: string,
  encoded: string | undefined): string[] | null {
  const projection = projectionFor(route);
  if (method !== "GET" || outcome !== "success" || !projection || encoded === undefined)
    return null;
  if (projection.collection && encoded === "none") return [];
  const fields = new Set(encoded === "none" ? [] : encoded.split(","));
  const canonical = fieldNames(projection).filter((key) => fields.has(key));
  if ((canonical.join(",") || "none") !== encoded ||
    Object.entries(projection.fields).some(([key, type]) =>
      (type === "number" || type === "string") && !fields.has(key)))
    return null;
  for (const [parent, child] of Object.entries(projection.children ?? {})) {
    if (canonical.some((field) => field.startsWith(`${parent}.`)) &&
      (!fields.has(parent) || Object.entries(child.required).some(([key, type]) =>
        type !== "nullable_string" && !fields.has(`${parent}.${key}`)))) return null;
  }
  return canonical;
}

export function hasUnresolvedNestedFields(route: string, fields: string[]): boolean {
  return Object.keys(projectionFor(route)?.children ?? {}).some((parent) =>
    fields.includes(parent) && !fields.some((field) => field.startsWith(`${parent}.`)));
}

export function responseCategoryPt(routeTemplate: string): string | undefined {
  return projectionFor(routeTemplate)?.categoryPt;
}

export function parseGatewayRequestObservation(message: string, outcome: string) {
  const match = /^Gateway (GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|OTHER) (\S+) completed(?: fields=([a-z0-9_.,]+))?$/
    .exec(message);
  if (!match) return undefined;
  const method = match[1]!;
  const routeTemplate = match[2]!;
  return { method, routeTemplate,
    responseFields: decodeResponseFieldEvidence(method, routeTemplate, outcome, match[3]) };
}
