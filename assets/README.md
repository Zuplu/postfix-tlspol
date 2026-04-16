To enable Prometheus metrics, add this to your `prometheus.yml` config:

```
scrape_configs:
  - job_name: postfix-tlspol
    static_configs:
      - targets:
          - 127.0.0.1:8642
```
