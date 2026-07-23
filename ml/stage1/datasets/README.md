# Stage-1 sample dataset

`sip-dataset-2026-06-02.csv` is a labeled **sample** (~115 rows) that runs the
training path (`ml/stage1/train.py`) end to end for smoke tests and CI.

The shipped model (`ml/deploy/models/`) is trained on the full per-source-IP
5-minute feature set (138 source-IP groups) aggregated from real campus-VM
traffic. That raw live-exposure corpus (third-party internet source addresses)
is kept governed rather than republished (see
[`../../../docs/DATA_PROVENANCE.md`](../../../docs/DATA_PROVENANCE.md)); the
published metrics are pinned to the committed training-run JSON.
