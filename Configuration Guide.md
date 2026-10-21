# Configuration Guide

The system allows customization of basic settings, database configurations, knowledge base settings, and LLM configurations.

All YAML configuration files are organized in the [`config/yaml/`](config/yaml/) directory:

## Configuration Files

- [`config/yaml/basic_config.yaml`](config/yaml/basic_config.yaml) – General system & Kali SSH settings.
- [`config/yaml/db_config.yaml`](config/yaml/db_config.yaml) – Local SQLite database settings.
- [`config/yaml/model_config.yaml`](config/yaml/model_config.yaml) – LLM (Large Language Model) API settings.
- [`config/yaml/kb_config.yaml`](config/yaml/kb_config.yaml) – Knowledge base & RAG settings.

## Configuration Structure

### 1. Basic Configuration (`config/yaml/basic_config.yaml`)

This section defines core settings for the system.

- Logging
  - `log_verbose`: Enable verbose logging (`true`/`false`).
  - `LOG_PATH`: Directory for storing logs.
- Mode
  - `mode`: Determines the system mode (`auto`, `manual`, `semi`).
- Network Settings
  - `http_default_timeout`: Timeout value for HTTP requests.
  - `default_bind_host`: Default binding address.
- Kali Linux Configuration
  - `hostname`: IP address of the Kali machine.
  - `port`: SSH port.
  - `username`: SSH username.
  - `password`: SSH password.
- Server Configuration
  - `api_server`: API server host and port.
  - `webui_server`: Web UI host and port.

### 2. Database Configuration (`config/yaml/db_config.yaml`)

This section defines local SQLite storage settings (serverless, no MySQL daemon required).

- SQLite
  - `sqlite_path`: Path to local SQLite database file (default: `data/penagent.db`).

### 3. Knowledge Base Configuration (`config/yaml/kb_config.yaml`)

Defines settings related to the knowledge base system.

- Vector Store
  - `default_vs_type`: Type of vector store (default: `milvus`).
  - `milvus`: Connection details (`uri`, `user`, `password`).
- Search Parameters
  - `top_n`: Number of results to retrieve.
  - `score_threshold`: Minimum score for results.
  - `search_params`: Search method parameters.
  - `index_params`: Indexing method parameters.
- Text Splitting
  - `text_splitter_dict`: Defines text splitters used for processing.
  - `text_splitter_name`: Selected text splitter method.

### 4. LLM Configuration (`config/yaml/model_config.yaml`)

Defines settings for the language model.

- API Settings
  - `api_key`: API key for accessing the model.
  - `base_url`: Base URL for OpenAI-compatible API requests.
  - `llm_model`: LLM provider (`openai` or `ollama`).
  - `llm_model_name`: Specific LLM model name.
- Processing Parameters
  - `temperature`: Model temperature.
  - `history_len`: Length of conversation history.
  - `timeout`: Timeout value for requests.
  - `proxies`: Proxy settings for API requests.
