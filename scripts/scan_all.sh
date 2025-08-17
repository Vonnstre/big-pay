name: aggressive-scan

on:
  workflow_dispatch:
    inputs:
      run_targets:
        description: 'Comma-separated list of targets (optional). If empty, uses hosts.txt'
        required: false
        default: ''

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install requests beautifulsoup4 tldextract dnspython httpx

      - name: Run full scan
        env:
          RUN_TARGETS: ${{ github.event.inputs.run_targets }}
        run: |
          chmod +x scripts/scan_all.sh
          ./scripts/scan_all.sh

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: scan-results
          path: findings/
