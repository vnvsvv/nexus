import createClient from "openapi-fetch";
import type { paths } from "./schema";

const client = createClient<paths>({
  baseUrl: import.meta.env.VITE_API_BASE || "/api/v1",
  headers: { Authorization: "Bearer " + (import.meta.env.VITE_API_TOKEN || "devtoken") },
});

export async function listIncidents(signal: AbortSignal) {
  const { data, response } = await client.GET("/incidents", { signal });
  if (!data) throw response;
  return data;
}

export async function getIncident(id: string, signal: AbortSignal) {
  const { data, response } = await client.GET("/incidents/{incident_id}", {
    params: { path: { incident_id: id } }, signal,
  });
  if (!data) throw response;
  return data;
}
