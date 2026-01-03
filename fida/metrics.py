from prometheus_client import Counter, Histogram

REQS = Counter("fida_requests_total", "Total requests", ["path","method","status"])
ISSUED = Counter("fida_events_issued_total", "Total events issued", ["tenant_id"])
LAT = Histogram("fida_request_latency_seconds", "Latency", ["path","method"])
