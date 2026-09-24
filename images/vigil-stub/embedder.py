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

        self.np = np
        self.tokenizer = Tokenizer.from_file(f"{model_dir}/tokenizer.json")
        self.session = ort.InferenceSession(
            f"{model_dir}/model_quantized.onnx",
            providers=["CPUExecutionProvider"],
        )
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
