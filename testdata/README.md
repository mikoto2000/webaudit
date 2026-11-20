# Synthetic corpus

Hand-authored calibration fixtures, not real incident logs or a held-out dataset. Each case is analyzed separately to avoid cross-case contamination. {i} expands to a distinct path; every generated record has a unique file/line and timestamp or query nonce. Includes benign clients, administration, a crawler and high-frequency API traffic. A rate anomaly on the benign high-frequency API is deliberately counted as an attack-detection false positive. Unsupported %u XSS encoding is deliberately counted as a false negative.

expected_outcome measures conservative decision policy, not server truth. ground_truth labels describe assumed synthetic backend behavior that cannot be recovered from these access logs; matching probable predictions are reported separately, with unknowns treated as abstentions. Two identical 200 observations have opposite assumed outcomes to demonstrate non-identifiability. No real-world accuracy claim is made.
