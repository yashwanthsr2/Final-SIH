#!/usr/bin/env bash
# CyberSentinel Model Evaluation & Training Script
export PYTHONPATH=.
echo "Evaluating existing models..."
python ml/evaluation/evaluate.py
