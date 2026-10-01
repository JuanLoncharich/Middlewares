"""all-MiniLM-L6-v2 via ONNX (quantized int8), mean-pooled + L2-normalized.

Same embedding model as the Vigil corpora loaded into the distributed Chroma
cluster, so cosine distances between scanner embeddings and corpus vectors
are directly comparable. Model files are baked into the image (no runtime
downloads): /models/tokenizer.json + /models/model_quantized.onnx.
"""


class Embedder:
    def __init__(self, model_dir):
        import numpy as np  # noqa: F401 - ensures the dep is really there
        from tokenizers import Tokenizer
        import onnxruntime as ort
        from ortutil import create_session

        self.np = np
        self.tokenizer = Tokenizer.from_file(f"{model_dir}/tokenizer.json")
        # Untruncated twin for windowed embedding of the whole payload.
        self.tokenizer_full = Tokenizer.from_file(f"{model_dir}/tokenizer.json")
        self.tokenizer_full.no_truncation()
        self.tokenizer_full.no_padding()
        self.session = create_session(ort, f"{model_dir}/model_quantized.onnx", "minilm")
        self.input_names = {i.name for i in self.session.get_inputs()}

    def encode(self, text):
        np = self.np
        enc = self.tokenizer.encode(text[:2000], add_special_tokens=True)
        ids = np.array([enc.ids], dtype=np.int64)
        mask = np.array([enc.attention_mask], dtype=np.int64)
        feed = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self.input_names:
            feed["token_type_ids"] = np.zeros_like(ids)
        out = self.session.run(None, feed)[0]  # (1, seq, 384) last_hidden_state
        m = mask[:, :, None].astype(np.float32)
        summed = (out * m).sum(axis=1)
        counts = np.clip(m.sum(axis=1), 1e-9, None)
        mean = summed / counts
        norm = np.clip(np.linalg.norm(mean, axis=1, keepdims=True), 1e-9, None)
        return (mean / norm)[0].tolist()

    def encode_windows(self, text, max_windows, window_tokens=126):
        """Embed EVERY overlapping window of `text` (batched). 126 content
        tokens + [CLS]/[SEP] = the same 128-token view encode() gets, so each
        window's vector is comparable to a single-prompt embedding.
        Returns (vectors, meta)."""
        import windowing

        np = self.np
        cls_id, sep_id, pad_id = windowing.special_ids(self.tokenizer_full)
        ids = self.tokenizer_full.encode(text, add_special_tokens=False).ids
        wins, truncated = windowing.split(ids, window_tokens, windowing.OVERLAP, max_windows)
        vectors = []
        for chunk in windowing.batches(wins, windowing.BATCH_SIZE):
            input_ids, mask = windowing.pad_batch(np, chunk, cls_id, sep_id, pad_id, fixed_len=window_tokens + 2)
            feed = {"input_ids": input_ids, "attention_mask": mask}
            if "token_type_ids" in self.input_names:
                feed["token_type_ids"] = np.zeros_like(input_ids)
            out = self.session.run(None, feed)[0]  # (n, seq, 384)
            m = mask[:, :, None].astype(np.float32)
            mean = (out * m).sum(axis=1) / np.clip(m.sum(axis=1), 1e-9, None)
            mean = mean / np.clip(np.linalg.norm(mean, axis=1, keepdims=True), 1e-9, None)
            vectors.extend(mean.tolist())
        return vectors, {"windows": len(wins), "truncated": truncated, "tokens": len(ids)}
