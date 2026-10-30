// Replay Server-Sent Events stream.
import { useEffect, useRef, useState } from "react";
import type { CampaignEvent, InvestigationEvent, PolicyEvent, ReplayFlowEvent } from "./types";

const FEED = 150;

/** Subscribes to the replay Server-Sent Events stream. */
export function useReplayStream() {
  const [flows, setFlows] = useState<ReplayFlowEvent[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignEvent[]>([]);
  const [investigations, setInvestigations] = useState<InvestigationEvent[]>([]);
  const [policies, setPolicies] = useState<PolicyEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const pending = useRef<ReplayFlowEvent[]>([]);

  useEffect(() => {
    const source = new EventSource("/api/replay/events");
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.addEventListener("flows", (e) => {
      pending.current.push(...(JSON.parse((e as MessageEvent).data).flows as ReplayFlowEvent[]));
    });
    source.addEventListener("campaign", (e) => {
      const event = JSON.parse((e as MessageEvent).data) as CampaignEvent;
      setCampaigns((list) => [event, ...list].slice(0, 40));
    });
    source.addEventListener("investigation", (e) => {
      const event = JSON.parse((e as MessageEvent).data) as InvestigationEvent;
      setInvestigations((list) => [event, ...list].slice(0, 40));
    });
    source.addEventListener("policy", (e) => {
      const event = JSON.parse((e as MessageEvent).data) as PolicyEvent;
      setPolicies((list) => [event, ...list].slice(0, 40));
    });
    // Rendering is throttled so a fast replay does not stall the page.
    const flush = setInterval(() => {
      if (!pending.current.length) return;
      const fresh = pending.current.slice(-FEED).reverse();
      pending.current = [];
      setFlows((list) => [...fresh, ...list].slice(0, FEED));
    }, 250);
    return () => { source.close(); clearInterval(flush); };
  }, []);

  return { flows, campaigns, investigations, policies, connected };
}
