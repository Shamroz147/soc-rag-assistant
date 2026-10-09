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
│   ├── rag_chain.py         # RAG chain + SOC prompt
│   └── app.py               # Streamlit UI
├── data/
│   └── mitre-attack/        # ATT&CK data files
└── vectorstore/             # FAISS index (gitignored)
```

## Setup

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com) installed and running
- Git

### 1. Clone the repository

```bash
git clone https://github.com/Shamroz147/soc-rag-assistant.git
cd soc-rag-assistant
```

### 2. Create a virtual environment and install dependencies

```bash
python -m venv venv

# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Download the local LLM

```bash
ollama pull llama3.2
```

### 4. Download the MITRE ATT&CK dataset

The raw dataset (~48 MB) is not included in the repository. Download `enterprise-attack.json` from the official [mitre/cti](https://github.com/mitre/cti/tree/master/enterprise-attack) repository and place it here:

```
data/mitre-attack/enterprise-attack.json
```

Or download it from the terminal:

```bash
curl -L -o data/mitre-attack/enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

> On Windows PowerShell, use `curl.exe` instead of `curl`.

### 5. Build the knowledge base

Parse the MITRE ATT&CK data into a CSV of techniques:

```bash
python data_loader.py
```

Then build the FAISS vector database and run a test analysis:

```bash
python rag_chain.py
```

This creates a `faiss_index/` folder in the project root. You can also rebuild it later from the app's sidebar.

### 6. Run the app

```bash
streamlit run main.py
```

The app opens in your browser at `http://localhost:8501`.

### Notes

- **Everything runs locally.** Log data is never sent to an external API.
- **The FAISS index is stored with Python `pickle`.** Loading a pickle file can execute arbitrary code, so only load `faiss_index/` files you created yourself.

## Screenshots

### Malicious log: encoded PowerShell launched from Word

<img width="1787" height="912" alt="Skjermbilde 2026-10-09 150415" src="https://github.com/user-attachments/assets/ce75f676-7584-440c-9bac-eb492218ad4b" />
<img width="1772" height="912" alt="Skjermbilde 2026-10-09 150443" src="https://github.com/user-attachments/assets/ca99f581-f2e7-4b83-8da0-3a1487b692d5" />


