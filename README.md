# SOC RAG Assistant

Automated Incident Response Assistant for SOC analysts.

Uses RAG (Retrieval-Augmented Generation) to connect security logs with the MITRE ATT&CK framework, helping analysts understand and respond to ongoing attacks.

## How It Works

1. Analyst pastes a suspicious log line (e.g., Windows Event 4688 process creation)
2. RAG system retrieves the most relevant MITRE ATT&CK techniques
3. LLM generates a response mapping the log to specific techniques and suggesting immediate actions

## Tech Stack

- **Orchestration:** LangChain
- **Vector DB:** FAISS (local)
- **Embeddings:** all-MiniLM-L6-v2 (HuggingFace, local)
- **LLM:** Ollama (local, e.g. Llama 3.2)
- **UI:** Streamlit

## Project Structure

```
soc-rag-assistant/
├── requirements.txt
├── .gitignore
├── README.md
├── src/
│   ├── data_loader.py      # Load & chunk MITRE ATT&CK data
│   ├── vector_store.py      # Embeddings + FAISS index
│   ├── rag_chain.py         # RAG chain + SOC prompt
│   └── app.py               # Streamlit UI
├── data/
│   └── mitre-attack/        # ATT&CK data files
└── vectorstore/             # FAISS index (gitignored)
```

## Setup

(Coming soon - we'll fill this in as we build)