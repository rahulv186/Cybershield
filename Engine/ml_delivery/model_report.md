# CyberShield ML Model Report

## Dataset

Dataset file:

`traintest.csv`

Total original records:

211,043

Exact duplicate records removed during training:

20,569

Records used after deduplication:

190,474

The original dataset was not modified.

---

# 1. Binary Classification

Binary classification determines whether network traffic is:

- Normal
- Attack

The binary models were trained using an 80/20 stratified train-test split.

## Binary Random Forest

Model:

`binary_random_forest_dedup.joblib`

Purpose:

Normal vs Attack

Test confusion matrix:

```text
                 Predicted
                 Normal  Attack

Actual Normal      8384      24
Actual Attack        25   29662