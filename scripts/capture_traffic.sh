#!/usr/bin/env bash
set -euo pipefail

output_dir="${OUTPUT_DIR:-data/pcaps}"
mkdir -p "${output_dir}"

echo "Planned: tcpdump capture wrapper will write rotating PCAPs under ${output_dir}."
