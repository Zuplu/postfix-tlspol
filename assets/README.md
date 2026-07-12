# Monitoring assets

## Prometheus scrape

The socketmap listener serves `GET /metrics` on the same address. Add a scrape job to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: postfix-tlspol
    scrape_interval: 15s
    scrape_timeout: 5s
    static_configs:
      - targets:
          - 127.0.0.1:8642
```

The dashboard filters by Prometheus `job` and `instance`, so one imported dashboard can cover multiple deployments without mixing similarly named targets.

## Grafana dashboard

Import the dashboard JSON directly:

- Dashboard JSON: [grafana-postfix-tlspol-dashboard.json](https://raw.githubusercontent.com/Zuplu/postfix-tlspol/refs/heads/main/assets/grafana-postfix-tlspol-dashboard.json)

For file provisioning, mount or copy:

- `grafana-postfix-tlspol-dashboard.json` to `/var/lib/grafana/dashboards/postfix-tlspol/`
- `provisioning/dashboards/postfix-tlspol.yaml` to `/etc/grafana/provisioning/dashboards/`

The optional `provisioning/datasources/prometheus.yaml` example provisions a Prometheus datasource with UID `prometheus`. Set `PROMETHEUS_URL` to the URL Grafana uses to reach Prometheus, for example `http://prometheus:9090`, before starting Grafana.

The provisioned dashboard is source-controlled. Edit the JSON in this directory and let Grafana reload it; UI changes are disabled by the provider to avoid configuration drift.
