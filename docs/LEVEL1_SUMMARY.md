# Level 1 summary

**Status: ready to submit, not submitted.** The API details are in the event WhatsApp group and are not in this repository. Deadline: 8:00 PM, 30 October.

## Text ready to submit

Measured values, from `data/reports/level1_summary.json`:

> **Partition:** official validation records, 114,185 rows. No tuning was done on them.
>
> **Baseline:** accuracy 0.99995, macro-F1 0.99982.
>
> **Agent 1 (threat detection):** CatBoost classifier over 70 flow features with balanced class weights, selected on an internal holdout. Reports predicted class and confidence. Per-class F1 is 0.99928 or higher.
>
> **Agent 2 (anomaly):** Isolation Forest trained on benign flows only, independent of Agent 1. Returns a percentile score against held-out benign flows, with the most deviant features as evidence. ROC-AUC 0.884, recall 55.9% at a 5.0% false-positive rate. It detects DoS and DDoS well but sees few brute-force or port-scan flows.
>
> **Agent 3 (evidence fusion):** keeps final class, evidence status and rationale separate. The agents agreed on 76.4% of flows. Disagreements are handled explicitly: a benign call with a high anomaly score becomes ANOMALY_ONLY and goes to review, and an attack call with no support is CLASSIFIER_ONLY and needs a higher confidence to block. Evidence status counts: MULTI_SIGNAL_CONFIRMED 53,923; AGREED_BENIGN 52,042; CAMPAIGN_ONLY 5,788; ANOMALY_ONLY 2,171; CLASSIFIER_ONLY 261. Simulated decisions: ALLOW 52,039; BLOCK 54,141; REVIEW 8,005.

## How to submit

The adapter refuses to send anything until it has the official format, and it does not guess.

1. Create `configs/submission.yaml` from the official instructions. Use this shape, filling each angle-bracketed value from those instructions:

   ```yaml
   url: <official endpoint>
   method: POST
   token_env: <environment variable holding your token, or remove this line>
   token_header: <official auth header name, or remove this line>
   payload_template:
     # Copy the official field names. Values in {braces} are filled from level1_summary.json.
     <official_accuracy_field>: "{accuracy}"
     <official_macro_f1_field>: "{macro_f1}"
   ```

2. Preview the payload. This sends nothing:

   ```bash
   .venv/bin/python -c "from backend.api.submission_adapter import submit; import json; print(json.dumps(submit(dry_run=True), indent=2))"
   ```

3. Check it against the instructions, then send it:

   ```bash
   .venv/bin/python -c "from backend.api.submission_adapter import submit; print(submit(dry_run=False))"
   ```

`configs/submission.yaml` is gitignored, but prefer `token_env` over putting a token in the file.
