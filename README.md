# Sagemcom modem metrics to vector

Pulls DOCSIS metrics as well as wireless, interface, and device metrics and sends to a Prometheus endpoint. Designed and tested with the modem _DNA Mesh WiFi F-3896 modeemi kaapelikoteihin_ but it should work with any Sagemcom modem with minimal modifications.

Uses vector running `program.py` in `exec` source outputting to Grafana Mimir.

Examples:

- [sample vector config](./config_sample_vector.yaml)
- [vector configuration for Speedtest.net metrics run every 12 hours](./config_sample_with_speedtest_vector.yaml) which uses the [SpeedTest.NET CLI](https://www.speedtest.net/apps/cli) (Note that you must run the speedtest.net cli first manually to accept the EULA).
- [vector configuration for using iperf](./config_sample_iperf3_vector.yaml)
- [vector configuration for ping exec](./config_sample_ping_vector.yaml)

# Diagnostics


```sh
# Manually run python script
clear ; SAGEMCOM_HOST=192.168.xxx.xxx SAGEMCOM_PASSWORD=xxx PYTHONPATH=~/Downloads/dna_modem_api/.venv/lib64/python3.12/site-packages/ python program.py | tee output_metrics.json

# run Vector locally, watching for changes
vector --verbose --watch-config --config vector.yaml

# tap
vector --verbose tap --outputs-of modem_api --meta --format logfmt
```