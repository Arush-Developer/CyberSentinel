"""Builds the evidence graph for one flow from measured agent, campaign and investigation output."""
from __future__ import annotations


def _node(node_id: str, kind: str, label: str, **data) -> dict:
    return {"id": node_id, "kind": kind, "label": label, "data": data}


def _edge(source: str, target: str, relation: str) -> dict:
    return {"id": f"{source}->{target}", "source": source, "target": target, "relation": relation}


def build_evidence_graph(detail: dict) -> dict:
    flow_id = detail["flow_id"]
    threat, anomaly, fusion = detail["threat"], detail["anomaly"], detail["fusion"]
    root = f"flow:{flow_id}"
    nodes = [_node(root, "flow", flow_id, destination_port=detail["network"].get("destination_port"))]
    edges: list[dict] = []

    a1 = "agent:threat"
    nodes.append(_node(a1, "agent", f"Agent 1: {threat['predicted_class']}", confidence=threat["confidence"]))
    edges.append(_edge(root, a1, "classified by"))
    a2 = "agent:anomaly"
    nodes.append(_node(a2, "agent", f"Agent 2: {anomaly['anomaly_score']:.3f}", is_anomaly=anomaly["is_anomaly"]))
    edges.append(_edge(root, a2, "scored by"))

    for item in anomaly["supporting_features"][:4]:
        fid = f"feature:{item['feature']}"
        nodes.append(_node(fid, "feature", item["feature"], measured_value=item["measured_value"],
                           benign_median=item["benign_median"], robust_z=item["robust_z"]))
        edges.append(_edge(a2, fid, f"z={item['robust_z']}"))

    port = detail["network"].get("destination_port")
    if port is not None:
        pid = f"port:{port:g}"
        nodes.append(_node(pid, "network", f"Port {port:g}"))
        edges.append(_edge(root, pid, "destination port"))
    for key, kind in (("source_ip", "source"), ("destination_ip", "destination")):
        value = detail["network"].get(key)
        if value:
            nid = f"{kind}:{value}"
            nodes.append(_node(nid, "network", str(value)))
            edges.append(_edge(root, nid, kind))

    campaign = detail.get("campaign")
    if campaign:
        cid = f"campaign:{campaign['campaign_id']}"
        nodes.append(_node(cid, "campaign", f"{campaign['campaign_id']}: {campaign['campaign_type']}",
                           flow_count=campaign["flow_count"], confidence=campaign["confidence"]))
        edges.append(_edge(root, cid, "member of"))
        for rel in campaign["relationships"][:3]:
            ends = [("source", rel["source"]), ("destination", rel["destination"])]
            for kind, value in ends:
                if value and f"{kind}:{value}" not in {n["id"] for n in nodes}:
                    nodes.append(_node(f"{kind}:{value}", "network", str(value)))
                    edges.append(_edge(cid, f"{kind}:{value}", f"{rel['flows']} flows"))

    investigation = detail.get("investigation")
    if investigation:
        inv = f"investigation:{investigation['investigation_id']}"
        nodes.append(_node(inv, "investigation", f"Investigation: {investigation['verdict']}"))
        edges.append(_edge(root, inv, "investigated"))
        for call in investigation["tool_calls"]:
            tid = f"tool:{call['tool']}"
            nodes.append(_node(tid, "tool", call["tool"], summary=call["result"]["summary"],
                               supports=call["result"]["supports"], available=call["result"]["available"]))
            edges.append(_edge(inv, tid, call["result"]["supports"]))

    final = "decision:fusion"
    nodes.append(_node(final, "decision", f"{fusion['final_class']} / {fusion['evidence_status']}",
                       policy=detail["policy"]["decision"]))
    edges.extend([_edge(a1, final, "evidence"), _edge(a2, final, "evidence")])
    if campaign:
        edges.append(_edge(f"campaign:{campaign['campaign_id']}", final, "evidence"))
    if investigation:
        edges.append(_edge(f"investigation:{investigation['investigation_id']}", final, "evidence"))
    policy = "decision:policy"
    nodes.append(_node(policy, "policy", detail["policy"]["decision"], rule=detail["policy"]["policy_rule"], reason=detail["policy"]["decision_reason"]))
    edges.append(_edge(final, policy, "simulated decision"))
    return {"nodes": nodes, "edges": edges}
