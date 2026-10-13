# Local analysis tools and models

Model weights are downloaded locally and are excluded from Git because of their size. Source cards, configs, tokenizers, and licenses are kept beside each checkpoint.

## Selected checkpoints

| Component | Local directory | Source and pinned revision | Notes |
|---|---|---|---|
| LLM4Decompile V2, 1.3B | `models/llm4decompile-1.3b-v2` | [Hugging Face](https://huggingface.co/LLM4Binary/llm4decompile-1.3b-v2), `a347dabcb1ea9f21c9339bd764c150262e993b95` | BF16 safetensors. Selected for this machine's 6 GB GPU; larger LLM4Decompile V2 checkpoints need substantially more memory. The included `LICENSE` applies the DeepSeek model license terms; check it before redistribution or use outside this project. |
| SecurityLLM, 7B AWQ | `models/securityllm-7b-awq` | [Hugging Face](https://huggingface.co/ZySec-AI/ZySec-7B-AWQ), `d9802d25c9f4aec0ca5ae7d68ff4b0c21f1cc423` | Official 4-bit AWQ safetensors, about 4.15 GB. Apache-2.0 per the publisher's model metadata. It may require a low context length and an AWQ-compatible runtime on a 6 GB GPU. |

The selected versions prioritize local hardware fit. LLM4Decompile's larger 9B V2 checkpoint reports stronger benchmark results, but its weights are too large for this GPU. SecurityLLM's full-precision 7B snapshot is about 14.5 GB, so the publisher's 4-bit AWQ checkpoint is used here.

## Ghidra

Official NSA release archive: `tools/ghidra_12.1.4_PUBLIC_20260921.zip` (Ghidra 12.1.4). It is kept as an archive and has not been extracted or launched.

Expected SHA-256: `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`.

## Download and safety notes

Model files came from pinned Hugging Face revisions and use the `safetensors` format. No model weights were loaded or executed. Temporary range-download chunks are removed automatically after assembly; if a transfer is interrupted, the `.parts` folder can be resumed by rerunning the downloader during this session.

## SHA-256

- LLM4Decompile: 54b2497da08eeedefe880e2bad040e754ca754a959f79cffce68131cf5bf9fa8
- SecurityLLM AWQ: 4537f2c2aa855163004dd7489d55a1ada5405a80acddda77cbeaf2935a575605
- Ghidra archive: ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
