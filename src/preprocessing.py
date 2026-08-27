#!/usr/bin/env python3
import json
import hashlib
import argparse
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field, asdict
from collections import Counter

try:
    from .schema import SCHEMA_VERSION, SUPPORTED_SCHEMAS
except ImportError:
    from schema import SCHEMA_VERSION, SUPPORTED_SCHEMAS


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
    fit: bool = False,
) -> Tuple[np.ndarray, int, dict]:
    with open(api_file) as f:
        api_data = json.load(f)
    with open(net_file) as f:
        net_data = json.load(f)

    metadata = api_data.get("metadata", {})
    version = metadata.get("schema_version")
    if version is None:
        raise ValueError(
            "capture without schema_version (legacy pre-2.0 capture); "
            "re-capture the sample or migrate the artifact"
        )
    if version not in SUPPORTED_SCHEMAS:
        raise ValueError(
            f"unsupported schema version {version!r} "
            f"(supported: {sorted(SUPPORTED_SCHEMAS)})"
        )
    label_str = metadata.get("label", "unlabeled")
    label_int = LABEL_MAP.get(label_str, -1)

    # merge API and network sequences, then sort by relative_time
    all_events = api_data.get("sequence", []) + net_data.get("sequence", [])
    all_events.sort(key=lambda e: e.get("relative_time", 0.0))

    if not all_events:
        empty = np.zeros((0, config.window_size, config.feature_dim), dtype=np.float32)
        return empty, label_int, metadata

    # training mode - build vocabulary
    if fit:
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


def collect_event_keys(api_file: Path, net_file: Optional[Path] = None) -> List[str]:
    if net_file is None:
        net_file = api_file.parent / api_file.name.replace(
            "_api_sequence.json", "_network_sequence.json"
        )

    keys: List[str] = []

    for path in (api_file, net_file):
        if not Path(path).exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for evt in data.get("sequence", []):
            keys.append(build_event_key(evt))
    return keys


def load_vocabulary(path: Path) -> Vocabulary:
    with open(path) as f:
        return Vocabulary.from_dict(json.load(f))


def preprocess_directory(
    input_dir: Path,
    config: PreprocessingConfig,
    output_dir: Optional[Path] = None,
    frozen_vocab: Optional[Vocabulary] = None,
) -> Tuple[np.ndarray, np.ndarray, Vocabulary, dict]:
    vocab = frozen_vocab if frozen_vocab is not None else Vocabulary()
    fitting = frozen_vocab is None
    all_windows = []
    all_labels = []
    sample_metadata = []

    # find all API sequence files
    api_files = sorted(input_dir.rglob("*_api_sequence.json"))
    if not api_files:
        print(f"[!] No API sequence files found in {input_dir}")
        return np.array([]), np.array([]), vocab, {}

    if fitting:
        for api_file in api_files:
            for key in collect_event_keys(api_file):
                vocab.add(key)

    for api_file in api_files:
        net_file = api_file.parent / api_file.name.replace("_api_sequence.json", "_network_sequence.json")

        if not net_file.exists():
            print(f"[!] Missing network sequence for {api_file.name}, skipping")
            continue

        try:
            windows, label, meta = preprocess_capture(
                api_file, net_file, vocab, config, fit=False,
            )
            if windows.shape[0] > 0:
                all_windows.append(windows)
                all_labels.extend([label] * windows.shape[0])
                
                sample_metadata.append({
                    "file": str(api_file),
                    "package": meta.get("package_name", ""),
                    "sha256": meta.get("apk_sha256", ""),
                    "label": meta.get("label", "unlabeled"),
                    "n_windows": windows.shape[0],
                    "termination_attempts": meta.get("termination_attempts", 0),
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
    parser.add_argument(
        "--layout",
        choices=["legacy", "multichannel"],
        default="multichannel",
        help="Encoding layout (N6). 'multichannel' emits per-channel token "
             "indices + numeric features with sample-level splits; 'legacy' "
             "keeps the single-matrix v1 behavior.",
    )
    parser.add_argument(
        "--vocab",
        type=Path,
        default=None,
        help="Frozen vocab.json to encode with (transform mode, legacy layout "
             "only). Omit to fit a new vocabulary on the input dir.",
    )

    args = parser.parse_args()
    config = PreprocessingConfig(window_size=args.window, stride=args.stride)
    if args.layout == "legacy":
        frozen = load_vocabulary(args.vocab) if args.vocab else None
        preprocess_directory(args.input_dir, config, args.output, frozen_vocab=frozen)
    else:
        if args.vocab:
            parser.error("--vocab applies to legacy layout only")
        preprocess_directory_multichannel(args.input_dir, config, output_dir=args.output)


CHANNELS = ("api", "network", "native")
_NETWORK_TYPES = frozenset({
    "network", "http", "https", "okhttp", "socket", "ssl",
})
_NATIVE_TYPES = frozenset({"native", "stalker"})
NUMERIC_DIM = 7
_NUMERIC_KEYS = ("has_path", "has_url", "has_payload", "port_norm",
                 "bytes_log", "exec_flag", "delta_norm")


def event_channel(event: dict) -> str:
    t = event.get("type", "")
    if t in _NETWORK_TYPES:
        return "network"
    if t in _NATIVE_TYPES:
        return "native"
    return "api"


def fit_channel_vocabularies(events: list) -> Dict[str, Vocabulary]:
    vocabs = {c: Vocabulary() for c in CHANNELS}
    for evt in events:
        vocabs[event_channel(evt)].add(build_event_key(evt))
    return vocabs


def _numeric_features(event: dict, prev_time: float) -> np.ndarray:
    f = np.zeros(NUMERIC_DIM, dtype=np.float32)
    f[0] = 1.0 if event.get("path") else 0.0
    f[1] = 1.0 if event.get("url") else 0.0
    f[2] = 1.0 if event.get("payload_hex") else 0.0

    try:
        f[3] = int(event.get("port", 0)) / 65535.0
    except (ValueError, TypeError):
        pass

    try:
        f[4] = np.log1p(float(event.get("bytes", 0))) / 20.0
    except (ValueError, TypeError):
        pass

    f[5] = 1.0 if event.get("is_exec") or event.get("action") == "mprotect_exec" else 0.0
    try:
        dt = float(event.get("relative_time", 0.0)) - prev_time
    except (TypeError, ValueError):
        dt = 0.0

    f[6] = min(max(dt, 0.0), 10.0) / 10.0
    return f


def encode_capture_multichannel(events, vocabs: Dict[str, Vocabulary],
                                config: PreprocessingConfig) -> dict:
    pad_id = vocabs[CHANNELS[0]].token2idx["<PAD>"]
    unk_ids = {c: vocabs[c].token2idx["<UNK>"] for c in CHANNELS}
    tokens = {c: [] for c in CHANNELS}
    numeric = np.zeros((len(events), NUMERIC_DIM), dtype=np.float32)
    active = {c: 0 for c in CHANNELS}
    unknown = {c: 0 for c in CHANNELS}

    prev_t = None
    for i, evt in enumerate(events):
        ch = event_channel(evt)
        key = build_event_key(evt)
        idx = vocabs[ch].encode(key)

        if idx == unk_ids[ch]:
            unknown[ch] += 1

        tokens[ch].append(idx)
        active[ch] += 1
        for other in CHANNELS:
            if other != ch:
                tokens[other].append(pad_id)

        t = evt.get("relative_time", 0.0)
        try:
            t = float(t)
        except (TypeError, ValueError):
            t = prev_t if prev_t is not None else 0.0
        numeric[i] = _numeric_features(evt, prev_t if prev_t is not None else t)
        prev_t = t

    unk_rate = {
        c: (unknown[c] / active[c]) if active[c] else 0.0 for c in CHANNELS
    }
    return {
        "tokens": {c: np.asarray(tokens[c], dtype=np.int32) for c in CHANNELS},
        "numeric": numeric,
        "unk_rate": unk_rate,
        "numeric_dim": NUMERIC_DIM,
        "_active": active,
    }


def assign_sample_splits(sha256s, ratios=(0.8, 0.15, 0.05)):
    assert abs(sum(ratios) - 1.0) < 1e-6
    cuts = (ratios[0], ratios[0] + ratios[1])
    out = {}
    for sha in sha256s:
        h = int(hashlib.md5(sha.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
        out[sha] = "train" if h < cuts[0] else "val" if h < cuts[1] else "test"
    return out


def _load_capture_events(api_file: Path):
    net_file = api_file.parent / api_file.name.replace(
        "_api_sequence.json", "_network_sequence.json"
    )

    if not net_file.exists():
        return None, None

    api_data = json.loads(api_file.read_text())

    meta = api_data.get("metadata", {})
    version = meta.get("schema_version")
    if version not in SUPPORTED_SCHEMAS:
        raise ValueError(f"unsupported schema version {version!r} in {api_file}")

    events = api_data.get("sequence", []) + json.loads(net_file.read_text()).get("sequence", [])
    events.sort(key=lambda e: e.get("relative_time", 0.0))
    return events, meta


def _write_capture(directory: Path, pkg: str, metadata: dict, sequence: list):
    directory.mkdir(parents=True, exist_ok=True)
    for kind in ("api", "network"):
        payload = {"metadata": dict(metadata), "sequence": sequence}
        (directory / f"{pkg}_{kind}_sequence.json").write_text(json.dumps(payload))


def preprocess_directory_multichannel(input_dir: Path,
                                      config: PreprocessingConfig,
                                      output_dir: Optional[Path] = None,
                                      unk_warn: float = 0.2) -> dict:
    input_dir = Path(input_dir)
    api_files = sorted(input_dir.rglob("*_api_sequence.json"))
    if not api_files:
        print(f"[!] No API sequence files found in {input_dir}")
        return {}

    captures = []
    all_keys = {c: [] for c in CHANNELS}

    for api_file in api_files:
        try:
            events, meta = _load_capture_events(api_file)
        except ValueError as e:
            print(f"  [!] {e}")
            continue
        if events is None:
            print(f"[!] Missing network sequence for {api_file.name}, skipping")
            continue

        captures.append((api_file, events, meta))
        for evt in events:
            all_keys[event_channel(evt)].append(build_event_key(evt))

    vocabs = {c: Vocabulary() for c in CHANNELS}
    for c in CHANNELS:
        for key in all_keys[c]:
            vocabs[c].add(key)

    shas = [meta.get("apk_sha256") or api_file.parent.name
            for api_file, _, meta in captures]
    splits = assign_sample_splits(shas)

    pad_id = vocabs["api"].token2idx["<PAD>"]
    win = config.window_size
    stride = config.stride

    def _windows(a, w=win, s=stride, pad_value=None):
        n = len(a)
        if n < w:
            if pad_value is None:
                shape = (w - n,) + a.shape[1:]
                fill = np.zeros(shape, dtype=a.dtype)
            else:
                fill = np.full(w - n, pad_value, dtype=a.dtype)
            return np.concatenate([a, fill])[np.newaxis, :]
        return np.stack([a[start:start + w]
                         for start in range(0, n - w + 1, s)])

    per_split = {s: {c: [] for c in CHANNELS} | {"numeric": [], "labels": []}
                 for s in ("train", "val", "test")}
    window_owners = []
    samples_meta = []

    for api_file, events, meta in captures:
        sha = meta.get("apk_sha256") or api_file.parent.name
        label = LABEL_MAP.get(meta.get("label", "unlabeled"), -1)
        enc = encode_capture_multichannel(events, vocabs, config)
        n_win = max(1, (len(events) - win) // stride + 1) if len(events) >= win else 1

        tw = {c: _windows(enc["tokens"][c], pad_value=pad_id) for c in CHANNELS}
        nw = _windows(enc["numeric"])
        split = splits[sha]

        for c in CHANNELS:
            per_split[split][c].append(tw[c])

        per_split[split]["numeric"].append(nw)
        per_split[split]["labels"].extend([label] * len(nw))
        window_owners.extend([(split, sha)] * len(nw))

        for c in CHANNELS:
            rate = enc["unk_rate"][c]
            if rate > unk_warn:
                print(f"  [!] HIGH UNK {api_file.stem} [{c}]: {rate:.0%}")

        samples_meta.append({
            "file": str(api_file), "package": meta.get("package_name", ""),
            "sha256": sha, "label": meta.get("label", "unlabeled"),
            "n_windows": int(nw.shape[0]), "split": split,
            "unk_rate": enc["unk_rate"],
            "events_active": enc["_active"],
        })

    if output_dir is None:
        output_dir = input_dir.parent / f"{input_dir.name}_mc"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    saved_shapes = {}
    for split, bundle in per_split.items():
        if not bundle["labels"]:
            continue

        for c in CHANNELS:
            arr = np.concatenate(bundle[c], axis=0) if bundle[c] else np.zeros((0, win), np.int32)
            np.save(output_dir / f"tokens_{c}_{split}.npy", arr)
            saved_shapes[f"{c}_{split}"] = arr.shape

        X = np.concatenate(bundle["numeric"], axis=0)
        y = np.array(bundle["labels"], dtype=np.int32)
        np.save(output_dir / f"numeric_{split}.npy", X)
        np.save(output_dir / f"labels_{split}.npy", y)
        saved_shapes[f"numeric_{split}"] = X.shape

    (output_dir / "splits.json").write_text(json.dumps(splits, indent=2))
    (output_dir / "vocab.json").write_text(json.dumps(
        {c: v.to_dict() for c, v in vocabs.items()}, indent=2))

    pipeline_meta = {
        "config": asdict(config),
        "layout": "multichannel",
        "numeric_dim": NUMERIC_DIM,
        "vocab_sizes": {c: len(v) for c, v in vocabs.items()},
        "samples": samples_meta,
    }

    (output_dir / "metadata.json").write_text(json.dumps(pipeline_meta, indent=2))
    print(f"[mc] wrote {output_dir}; shapes={saved_shapes}")

    return {"splits": splits, "window_owners": window_owners,
            "vocabs": vocabs, "metadata": pipeline_meta}


if __name__ == "__main__":
    main()
