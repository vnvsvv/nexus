import React from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider, Link, Outlet, Navigate, useLoaderData, useRouteError, isRouteErrorResponse } from "react-router-dom";
import { getIncident, listIncidents } from "./api";
import "./style.css";

function Layout() {
  return <><header><b>NEXUS</b><span>Incident workspace</span></header><main><Outlet/></main></>;
}

function ErrorView({ detail = false }: { detail?: boolean }) {
  const error = useRouteError();
  return <section><h1>{detail && isRouteErrorResponse(error) && error.status === 404 ? "Incident not found" : "Unable to load incidents"}</h1>
    <p>Check the incident address and the API connection.</p><Link to="/incidents">Incident list</Link> · <button onClick={() => location.reload()}>Retry</button></section>;
}

function List() {
  const {items, total} = useLoaderData() as Awaited<ReturnType<typeof listIncidents>>;
  return <><h1>Incidents</h1><p>{total} {total === 1 ? "incident" : "incidents"} reported</p>
    {items.length === 0 ? <section>No incidents to display.</section> : items.map(i =>
      <article key={i.incident_id}><div className="meta"><strong>{i.severity} severity</strong><span>{i.status}</span><time>{i.detected_at_utc}</time></div>
        <h2><Link to={"/incidents/" + encodeURIComponent(i.incident_id)}>{i.title}</Link></h2>
        <p>{i.endpoint_id} · {i.os} · {i.confidence} confidence</p>
        <div className="meta">{Object.entries(i.correlation_summary).map(([k,v]) => <span key={k}>{k.replaceAll("_"," ")} {v}</span>)}<span>Local response: {i.local_response_status || "unreported"}</span></div></article>)}</>;
}

function Detail() {
  const view = useLoaderData() as Awaited<ReturnType<typeof getIncident>>;
  const {incident,server} = view;
  const events = [...incident.evidence].sort((a,b) => a.event.timestamp_utc.localeCompare(b.event.timestamp_utc));
  return <><Link to="/incidents">← Incidents</Link><h1 className="title">{incident.title}</h1>
    <div className="meta"><strong>{incident.severity} severity</strong><span>{incident.status}</span><span>{incident.confidence} confidence</span></div>
    <p>{incident.endpoint_id} · {incident.os} · {incident.detected_at_utc}</p>
    <section><h2>Evidence timeline</h2>{events.length === 0 && <p>No events recorded.</p>}
      {events.map(e => <div className="row" key={e.event_id}><time>{e.event.timestamp_utc.slice(11)} </time><div><b>{e.event.event_type.replaceAll("_"," ")}</b> · {e.role}<p>{e.event.file?.path || e.event.command_line || e.event.binary || e.event_id}</p></div></div>)}</section>
    <section><h2>Network evidence</h2>{server.network_evidence.length === 0 && <p>No gateway evidence recorded.</p>}
      {server.network_evidence.map(({gateway_connection:g,flows}) => <div key={g.gateway_connection_id}><p>{g.gateway_connection_id}</p>{flows?.map(f => <p key={f.flow_id}>{f.src_ip}:{f.src_port} → {f.dst_ip}:{f.dst_port} · {f.application_name} {f.ml && " · ML " + f.ml.label + " (score " + f.ml.score + ")"}</p>)}</div>)}
      {server.correlations.map(c => <p key={c.connection_id}>Correlation: {c.state} · {c.basis} {c.note}</p>)}</section>
    <section><h2>Evidence gaps</h2>{incident.gaps.length ? incident.gaps.map((g,i) => <p key={i}><b>{g.code}</b> · {g.message}</p>) : <p>No gaps recorded.</p>}</section>
    <details><summary>Full incident record</summary><pre>{JSON.stringify(view,null,2)}</pre></details></>;
}

const router = createBrowserRouter([{path:"/",element:<Layout/>,children:[
  {index:true,element:<Navigate replace to="/incidents"/>},
  {path:"incidents",loader:({request}) => listIncidents(request.signal),element:<List/>,errorElement:<ErrorView/>},
  {path:"incidents/:id",loader:({params,request}) => getIncident(params.id!,request.signal),element:<Detail/>,errorElement:<ErrorView detail/>},
]}]);
createRoot(document.getElementById("root")!).render(<React.StrictMode><RouterProvider router={router} fallbackElement={<p>Loading incidents…</p>}/></React.StrictMode>);
