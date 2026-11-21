const publicInstitutions = new Map([
  ["Banco Jacarandá", "Banco de origem"],
  ["Banco de origem", "Banco de origem"],
  ["Banco Ipê", "Banco Ipê"],
  ["Banco Aroeira", "Banco Aroeira"],
  ["Saída externa", "Saída externa"],
]);

export function presentationInstitution(name: string): string {
  return publicInstitutions.get(name) ?? "Instituição externa";
}
