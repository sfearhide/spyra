#!/usr/bin/env python3
"""
LSTM Preprocessing Pipeline for Spyra

Converts raw JSON capture output into fixed-dimensional tensors suitable
for LSTM training. Addresses the tokenization gap identified in the thesis
review:

  1. API-name vocabulary and integer tokenizer
  2. Strategy for variable-length string fields (hash/truncate/discard)
  3. Normalization for timestamp / relative_time fields
  4. Defined sequence-length window (sliding window of N events)
"""

import json
import hashlib
import argparse
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field, asdict
from collections import Counter


# vocabulary & tokenizer

RESERVED_TOKENS = ["<PAD>", "<UNK>", "<SOS>", "<EOS>"]

def build_event_key(event: dict) -> str:
    etype = event.get("type", "unknown")
    action = event.get("action", "")
    func = event.get("func", "")  # native hooks use 'func' not 'action'
    key = etype
    if action:
        key += ":" + action
    elif func:
        key += ":" + func
    return key


class Vocabulary:
    def __init__(self):
        self.token2idx: Dict[str, int] = {}
        self.idx2token: Dict[int, str] = {}
        for i, tok in enumerate(RESERVED_TOKENS):
            self.token2idx[tok] = i
            self.idx2token[i] = tok
        self._next_idx = len(RESERVED_TOKENS)

    def add(self, token: str) -> int:
        if token not in self.token2idx:
            self.token2idx[token] = self._next_idx
            self.idx2token[self._next_idx] = token
            self._next_idx += 1
        return self.token2idx[token]

    def encode(self, token: str) -> int:
        return self.token2idx.get(token, self.token2idx["<UNK>"])

    def __len__(self):
        return self._next_idx

    def to_dict(self) -> dict:
        return {"token2idx": self.token2idx, "idx2token": {str(k): v for k, v in self.idx2token.items()}}

    @classmethod
    def from_dict(cls, d: dict) -> "Vocabulary":
        v = cls()
        v.token2idx = d["token2idx"]
        v.idx2token = {int(k): v_ for k, v_ in d["idx2token"].items()}
        v._next_idx = max(v.idx2token.keys()) + 1 if v.idx2token else len(RESERVED_TOKENS)
        return v


# feature extraction
FEATURE_DIM = 10


def _hash_to_float(s: str, buckets: int = 256) -> float:
    if not s:
        return 0.0
    h = int(hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()[:8], 16)
    return (h % buckets) / buckets


def extract_features(event: dict, vocab: Vocabulary, max_time: float) -> np.ndarray:
    features = np.zeros(FEATURE_DIM, dtype=np.float32)

    # token ID
    key = build_event_key(event)
    features[0] = float(vocab.encode(key))

    rel_time = event.get("relative_time", 0.0)
    features[1] = min(rel_time / max_time, 1.0) if max_time > 0 else 0.0

    tid = str(event.get("thread_id", ""))
    features[2] = _hash_to_float(tid) # thread ID hash
    features[3] = 1.0 if event.get("path") else 0.0 # has path
    features[4] = 1.0 if event.get("url") else 0.0 # has URL
    features[5] = 1.0 if event.get("payload_hex") else 0.0 # has payload

    # port
    port = event.get("port", 0)
    try:
        features[6] = int(port) / 65535.0
    except (ValueError, TypeError):
        features[6] = 0.0

    nbytes = event.get("bytes", 0)
    try:
        features[7] = np.log1p(float(nbytes)) / 20.0
    except (ValueError, TypeError):
        features[7] = 0.0

    features[8] = 1.0 if event.get("is_exec") or event.get("action") == "mprotect_exec" else 0.0 # is executable protection

    # sequence pos
    seq = event.get("seq", 0)
    try:
        features[9] = min(float(seq) / 10000.0, 1.0)
    except (ValueError, TypeError):
        features[9] = 0.0
    return features


def create_windows(
    features: np.ndarray,
    window_size: int = 200,
    stride: int = 50,
) -> np.ndarray:
    seq_len = features.shape[0]
    if seq_len == 0:
        return np.zeros((0, window_size, features.shape[1] if features.ndim > 1 else FEATURE_DIM), dtype=np.float32)

    if seq_len < window_size:
        pad = np.zeros((window_size - seq_len, features.shape[1]), dtype=np.float32)
        features = np.concatenate([features, pad], axis=0)
        return features[np.newaxis, :, :]  # single window

    windows = []
    for start in range(0, seq_len - window_size + 1, stride):
        windows.append(features[start : start + window_size])
    return np.array(windows, dtype=np.float32)


# pipeline

LABEL_MAP = {
    "benign": 0,
    "malware": 1,
    "unlabeled": -1,
}


@dataclass
class PreprocessingConfig:
    window_size: int = 200
    stride: int = 50
    feature_dim: int = FEATURE_DIM
    max_time_default: float = 600.0  # 10 min as default normalization cap


def preprocess_capture(
    api_file: Path,
    net_file: Path,
    vocab: Vocabulary,
    config: PreprocessingConfig,
) -> Tuple[np.ndarray, int, dict]:
    with open(api_file) as f:
        api_data = json.load(f)
    with open(net_file) as f:
        net_data = json.load(f)

    metadata = api_data.get("metadata", {})
    label_str = metadata.get("label", "unlabeled")
    label_int = LABEL_MAP.get(label_str, -1)

    # merge API and network sequences, then sort by relative_time
    all_events = api_data.get("sequence", []) + net_data.get("sequence", [])
    all_events.sort(key=lambda e: e.get("relative_time", 0.0))

    if not all_events:
        empty = np.zeros((0, config.window_size, config.feature_dim), dtype=np.float32)
        return empty, label_int, metadata

    # training mode - build vocabulary
    for evt in all_events:
        key = build_event_key(evt)
        vocab.add(key)

    max_time = max(e.get("relative_time", 0.0) for e in all_events)
    max_time = max(max_time, 1.0)  # avoid division by zero

    # extract features
    feature_matrix = np.array(
        [extract_features(evt, vocab, max_time) for evt in all_events],
        dtype=np.float32,
    )

    windows = create_windows(feature_matrix, config.window_size, config.stride)
    return windows, label_int, metadata


def preprocess_directory(
    input_dir: Path,
    config: PreprocessingConfig,
    output_dir: Optional[Path] = None,
) -> Tuple[np.ndarray, np.ndarray, Vocabulary, dict]:
    vocab = Vocabulary()
    all_windows = []
    all_labels = []
    sample_metadata = []

    # find all API sequence files
    api_files = sorted(input_dir.rglob("*_api_sequence.json"))
    if not api_files:
        print(f"[!] No API sequence files found in {input_dir}")
        return np.array([]), np.array([]), vocab, {}

    for api_file in api_files:
        net_file = api_file.parent / api_file.name.replace("_api_sequence.json", "_network_sequence.json")
        
        if not net_file.exists():
            print(f"[!] Missing network sequence for {api_file.name}, skipping")
            continue
        
        try:
            windows, label, meta = preprocess_capture(api_file, net_file, vocab, config)
            if windows.shape[0] > 0:
                all_windows.append(windows)
                all_labels.extend([label] * windows.shape[0])
                
                sample_metadata.append({
                    "file": str(api_file),
                    "package": meta.get("package_name", ""),
                    "sha256": meta.get("apk_sha256", ""),
                    "label": meta.get("label", "unlabeled"),
                    "n_windows": windows.shape[0],
                })
                print(f"  [+] {api_file.parent.name}: {windows.shape[0]} windows, label={meta.get('label', 'unlabeled')}")
        except Exception as e:
            print(f"  [!] Error processing {api_file}: {e}")
            continue

    if not all_windows:
        return np.array([]), np.array([]), vocab, {}

    X = np.concatenate(all_windows, axis=0)
    y = np.array(all_labels, dtype=np.int32)

    pipeline_meta = {
        "config": asdict(config),
        "vocab_size": len(vocab),
        "total_windows": X.shape[0],
        "total_samples": len(sample_metadata),
        "label_distribution": dict(Counter(all_labels)),
        "samples": sample_metadata,
    }

    if output_dir is None:
        output_dir = input_dir.parent / f"{input_dir.name}_preprocessed"
    output_dir.mkdir(parents=True, exist_ok=True)

    np.save(output_dir / "sequences.npy", X)
    np.save(output_dir / "labels.npy", y)
    
    with open(output_dir / "vocab.json", "w") as f:
        json.dump(vocab.to_dict(), f, indent=2)
    
    with open(output_dir / "metadata.json", "w") as f:
        json.dump(pipeline_meta, f, indent=2, default=str)

    print(f"\n[*] Preprocessing complete:")
    print(f"    Sequences: {X.shape}  (windows x timesteps x features)")
    print(f"    Labels:    {y.shape}  distribution={dict(Counter(all_labels))}")
    print(f"    Vocab:     {len(vocab)} tokens")
    print(f"    Output:    {output_dir}")
    return X, y, vocab, pipeline_meta


def main():
    parser = argparse.ArgumentParser(
        description="Preprocess Spyra capture data for LSTM training",
    )
    parser.add_argument("input_dir", type=Path, help="Directory containing capture JSON files")
    parser.add_argument("--window", type=int, default=200, help="Sliding window size (default: 200)")
    parser.add_argument("--stride", type=int, default=50, help="Sliding window stride (default: 50)")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output directory")

    args = parser.parse_args()
    config = PreprocessingConfig(window_size=args.window, stride=args.stride)
    preprocess_directory(args.input_dir, config, args.output)


if __name__ == "__main__":
    main()
