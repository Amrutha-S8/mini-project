# Local Embedding Model — documentation before selection

**Status:** proposal for owner decision (DD-08 decision 6). **No model has
been downloaded, installed, run or tested.** The sandbox has no package or
model access (`INTEGRATIONS_ONLY`), and the Hugging Face model pages returned
HTTP 403 to the fetch tool, so the figures below come from search results and
third-party mirrors of the model files, cited inline. Every figure must be
re-checked against the primary model card and the downloaded files on the day
of installation.

## 1. Requirement

Embeddings must be produced on the household machine. No private visitor
record, biometric data or household security event may be sent to an
external embedding API. The integration is Sentence Transformers through
LangChain's `HuggingFaceEmbeddings` (`langchain-huggingface`), which runs
models locally with no API key
([LangChain docs](https://docs.langchain.com/oss/python/integrations/embeddings/sentence_transformers)).

## 2. Candidates

| | **BAAI/bge-small-en-v1.5** (proposed) | sentence-transformers/all-MiniLM-L6-v2 (fallback) |
|---|---|---|
| Version | `v1.5`; Hub commit revision to be pinned at download | `v2`; Hub commit revision to be pinned at download |
| Licence | MIT, per mirrors that copy the original licence ([DakeraAI mirror](https://huggingface.co/DakeraAI/bge-small-en-v1.5)) | Apache-2.0, per mirrors ([DakeraAI mirror](https://huggingface.co/DakeraAI/all-MiniLM-L6-v2); [cstr port](https://huggingface.co/cstr/all-MiniLM-L6-v2-hailo10h)) |
| Parameters | about 33M ([cstr GGUF card](https://huggingface.co/cstr/bge-small-en-v1.5-GGUF)) | 22.7M ([superlinked reference](https://superlinked.com/glossary/what-is-all-minilm-l6-v2)) |
| Output dimension | 384 | 384 |
| Input limit | 512 tokens ([collection note](https://huggingface.co/collections/bbrooksvc/local-document-search-embeddings-reranking-and-honest-checks)) | Shorter than bge-small (to be confirmed from the card) |
| Weights file | `model.safetensors` 133.5 MB fp32; a quantised ONNX export is listed at 34.0 MB ([DakeraAI mirror](https://huggingface.co/DakeraAI/bge-small-en-v1.5)) | `model.safetensors` 90.9 MB ([DakeraAI mirror](https://huggingface.co/DakeraAI/all-MiniLM-L6-v2)) |
| Full repository | Not measured | About 1 GB with every format; only the needed files should be downloaded ([monju-lab note](https://huggingface.co/monju-lab/all-MiniLM-L6-v2-onnx)) |
| Usage note | A query instruction prefix is recommended for short-query retrieval ([cstr GGUF card](https://huggingface.co/cstr/bge-small-en-v1.5-GGUF)) | None |

*Content was rephrased for compliance with licensing restrictions.*

**Why bge-small is proposed:** permissive licence, small enough for a CPU,
and a 512-token limit that fits the planned chunk sizes. Retrieval quality on
this project's documents has **not** been measured; the evaluation in
`app/ai/core/evaluation.py` will compare both candidates once one can be run.

**Licence caveat:** the model licence covers the weights. The training
datasets have their own terms, which were not reviewed. For a household
system this is a low risk, but the licence text itself must be read from the
primary model page before download, as was required for InsightFace (DD-04).

## 3. Hardware and storage

| Item | Estimate | Measured? |
|---|---|---|
| GPU | Not needed; CPU inference | No |
| Model on disk | about 135 MB (bge-small weights plus tokenizer) | No |
| Runtime on disk | Sentence Transformers recommends Python 3.10+, PyTorch 2.2+ and transformers v5 ([installation docs](https://github.com/huggingface/sentence-transformers/blob/master/docs/installation.md)); the CPU PyTorch wheel is large, size not measured | No |
| RAM | Weights (about 135 MB fp32) plus PyTorch overhead; expected well under 1 GB for this model, **unmeasured** | No |
| Lower-footprint option | Sentence Transformers can load an ONNX backend for CPU use ([efficiency docs](https://github.com/huggingface/sentence-transformers/blob/main/docs/sentence_transformer/usage/efficiency.rst)); whether it removes the PyTorch install was not verified | No |

## 4. Running without sending data out

Inference is local. The only network use is the one-time download. After
that the deployment must run offline:

- download once on a trusted machine, pin the Hub revision, record the
  SHA-256 of every file, and copy the files in with the wheelhouse;
- load with `local_files_only=True`, `trust_remote_code=False`, safetensors
  weights only;
- set `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1` and
  `HF_HUB_DISABLE_TELEMETRY=1`; ChromaDB with `anonymized_telemetry=False`;
- the live check `live_local_embeddings` in the AI gate record (DD-08
  decision 7) must show the model loading and embedding with the network
  disabled before the AI tier may be enabled.

## 5. Decision needed

Approve `BAAI/bge-small-en-v1.5` (or the fallback) for download once package
access returns. Until then nothing is downloaded, and no retrieval quality
or performance claim is made.
