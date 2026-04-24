To enable Prometheus metrics, add this to your `prometheus.yml` config:

```
scrape_configs:
  - job_name: postfix-tlspol
    static_configs:
      - targets:
          - 127.0.0.1:8642
```

To use the Grafana dashboard from this repo, import:

- Dashboard JSON: [grafana-postfix-tlspol-dashboard.json](https://raw.githubusercontent.com/Zuplu/postfix-tlspol/refs/heads/main/assets/grafana-postfix-tlspol-dashboard.json)
