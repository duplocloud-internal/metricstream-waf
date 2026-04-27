# SIEM Correlation Guide — MetricStream WAF

## Log Sources

| Source | Log group / bucket | Correlation key |
|---|---|---|
| WAF block events | `/aws/waf/metricstream-prod` | `requestId` |
| ALB access logs | `s3://alb-logs-metricstream/` | `request_id` |
| Application logs | Application log group | `x-request-id` header |

## WAF Log Format (Key Fields)

```json
{
  "timestamp": 1713598800000,
  "action": "BLOCK",
  "terminatingRuleId": "AWSManagedRulesCommonRuleSet",
  "terminatingRuleMatchDetails": [
    {
      "conditionType": "SQL_INJECTION",
      "location": "QUERY_STRING",
      "matchedData": ["detected-pattern"]
    }
  ],
  "httpRequest": {
    "clientIp": "203.0.113.50",
    "country": "US",
    "uri": "/api/data",
    "httpMethod": "GET",
    "requestId": "abc123def456",
    "headers": [
      { "name": "Host", "value": "customer-a.metricstream.com" }
    ]
  }
}
```

## SIEM Correlation Rules

### Splunk SPL — Join WAF + ALB logs

```spl
index=waf action="BLOCK"
| join type=left request_id
    [search index=alb | fields request_id, elb_status_code, target_processing_time]
| table _time, clientIp, uri, terminatingRuleId, elb_status_code, target_processing_time
| sort -_time
```

### Kibana / OpenSearch — Correlate by requestId

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "action": "BLOCK" } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ]
    }
  },
  "aggs": {
    "by_rule": {
      "terms": { "field": "terminatingRuleId.keyword" }
    },
    "by_customer": {
      "terms": { "field": "httpRequest.headers.host.value.keyword" }
    }
  }
}
```

## Recommended SIEM Dashboards

1. **WAF Block Rate Over Time** — line chart, grouped by rule
2. **Top Blocked IPs** — table with geo enrichment
3. **Blocks by Customer** — bar chart filtered by Host header
4. **False Positive Trend** — manual override count over time
5. **Rule Override Status** — table: which rules are in COUNT mode and why
6. **Geographic Attack Map** — map of `httpRequest.country`

## Alert Rules

| Alert | Condition | Priority |
|---|---|---|
| IP blocked > 100 times in 5 min | WAF log count by IP | P3 |
| Customer completely blocked (0 allowed) | Allowed requests drop to 0 for a hostname | P1 |
| New attack pattern detected | terminatingRuleMatchDetails contains new pattern | P2 |
| WAF logging stopped | No new WAF log events for > 15 min | P1 |
