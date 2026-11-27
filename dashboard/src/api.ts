import createClient from "openapi-fetch";
import type { paths } from "./schema";

const client = createClient<paths>({
  baseUrl: "/api/v1",

});

export async function listIncidents(signal: AbortSignal) {
  const { data, response } = await client.GET("/incidents", { signal });
  if (!data) throw new Response(null, { status: response.status, statusText: response.statusText });
  return data;
}

export async function getIncident(id: string, signal: AbortSignal) {
  const { data, response } = await client.GET("/incidents/{incident_id}", {
    params: { path: { incident_id: id } }, signal,
  });
  if (!data) throw new Response(null, { status: response.status, statusText: response.statusText });
  return data;
}
