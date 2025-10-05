#!/bin/sh

#!/usr/bin/env bash
while true; do
  # /usr/local/bin/cleanup-gs-tmp.sh
  echo "Waiting for a bit"
  sleep 10
  echo "Sending reports..."
  python3 reporter.py --scan-dir=fuzz_test --triager=fuzz_test/main --email=sontapaa.jokulainen@gmail.com --max-retries=20
  # find /tmp -maxdepth 1 -name 'gs_*' -mmin +60 -print -exec rm -rf {} +
  # find /tmp -maxdepth 1 -name 'libfuzzer*' -mmin +60 -print -exec rm -rf {} +
  # sudo python3 stuff.py /var/coredumps --delete pdf_fuzzer --yes --keep afl-fuzz
done

