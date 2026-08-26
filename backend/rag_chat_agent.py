import os
import time
from typing import List, Dict, Generator

from langchain_community.vectorstores import Chroma
from langchain_core.embeddings import Embeddings

from google import genai
from google.genai import types


class GeminiEmbeddings(Embeddings):
    """
    Custom LangChain-compatible embeddings class that talks to Gemini
    directly through the google-genai SDK, with api_version='v1alpha' so it
    works with the newer "AQ." format API keys.
    """

    def __init__(self, client: genai.Client, model: str = "models/embedding-001"):
        self.client = client
        self.model = model

    def _embed(self, text: str) -> List[float]:
        result = self.client.models.embed_content(
            model=self.model,
            contents=text
        )
        return result.embeddings[0].values

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> List[float]:
        return self._embed(text)


def _is_auth_error(error_text: str) -> bool:
    return any(marker in error_text for marker in
               ["API_KEY_INVALID", "401", "UNAUTHENTICATED",
                "ACCESS_TOKEN_TYPE_UNSUPPORTED"])


# Current-generation GA models as of Aug 2026. Older 2.x models
# (e.g. gemini-2.5-flash) have been retired for new API users —
# keep this list updated if Google retires these too.
CHAT_MODELS_TO_TRY = ["gemini-3.6-flash", "gemini-3.5-flash-lite"]


class RAGChatAssistant:
    def __init__(self, vectorstore_dir: str = "./chroma_db", api_key: str = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

        # Single shared client for both embeddings and chat generation.
        # v1alpha is required for the newer "AQ." format API keys —
        # this is the same setup already working in remediation_agent.py.
        self.client = genai.Client(
            api_key=self.api_key,
            http_options=types.HttpOptions(api_version="v1alpha")
        )

        # Expert System Prompt requested by your professor
        self.system_prompt = (
            "You are an expert Code Review and Security Analysis Assistant.\n\n"
            "Your responsibilities:\n"
            "- Explain what the code does.\n"
            "- Detect bugs.\n"
            "- Identify code smells.\n"
            "- Find security vulnerabilities (OWASP Top 10).\n"
            "- Suggest performance improvements.\n"
            "- Recommend best coding practices.\n"
            "- Provide corrected code when needed.\n"
            "Remember the previous conversation and answer follow-up questions based on earlier messages."
        )

        # Load Vector Store if available, else handle gracefully
        try:
            embeddings = GeminiEmbeddings(client=self.client, model="models/embedding-001")
            self.vectorstore = Chroma(persist_directory=vectorstore_dir, embedding_function=embeddings)
            self.retriever = self.vectorstore.as_retriever(search_kwargs={"k": 3})
        except Exception as e:
            print(f"Warning: Could not load ChromaDB vectorstore: {e}")
            self.retriever = None

    def _format_history(self, chat_history: List[Dict[str, str]]) -> str:
        """Turns the chat history list into plain text for the prompt."""
        if not chat_history:
            return "(no previous messages)"
        lines = []
        for msg in chat_history:
            role = "User" if msg["role"] == "user" else "Assistant"
            lines.append(f"{role}: {msg['content']}")
        return "\n".join(lines)

    def _retrieve_context(self, query: str) -> str:
        """
        Pulls relevant chunks from the knowledge base for this query.
        IMPORTANT: this makes its own Gemini call (for the query embedding),
        so it can fail the same way the chat call can — never leave this
        unguarded, or auth errors here bypass the friendly handling below
        and leak a raw Google error up to the API response.
        """
        if not self.retriever:
            return "(knowledge base not available)"
        try:
            try:
                docs = self.retriever.invoke(query)
            except AttributeError:
                # older LangChain versions use get_relevant_documents instead of invoke
                docs = self.retriever.get_relevant_documents(query)
        except Exception as e:
            error_text = str(e)
            if _is_auth_error(error_text):
                raise RuntimeError(
                    "Could not authenticate with Gemini while searching the knowledge base. "
                    "Check that GEMINI_API_KEY in .env is current and valid."
                ) from e
            # Any other retrieval error (e.g. empty/corrupt vectorstore) —
            # don't let it kill the whole chat, just skip retrieval.
            print(f"Warning: knowledge base retrieval failed: {e}")
            return "(knowledge base lookup failed for this query)"

        if not docs:
            return "(no relevant knowledge base entries found)"

        return "\n\n".join(d.page_content for d in docs)

    def get_response(self, query: str, chat_history: List[Dict[str, str]], code_context: str = "") -> str:
        """
        Answers developer queries using RAG retrieval combined with expert code
        review instructions and code context — returning a full string response.
        """
        full_text = ""
        for chunk in self.stream_response(query, chat_history, code_context):
            full_text += chunk
        return full_text

    def stream_response(self, query: str, chat_history: List[Dict[str, str]], code_context: str = "") -> Generator[str, None, None]:
        """
        Streams expert developer query responses token-by-token using Gemini's streaming capabilities,
        matching the speed and responsiveness of the streaming reports.
        """
        try:
            retrieved_context = self._retrieve_context(query)
            history_text = self._format_history(chat_history)

            full_prompt = f"""{self.system_prompt}

--- Relevant Secure Coding Knowledge Base Entries ---
{retrieved_context}

--- Active Code Context ---
{code_context if code_context else "(none provided)"}

--- Conversation So Far ---
{history_text}

--- User Query ---
{query}
"""

            last_error = None
            for model_name in CHAT_MODELS_TO_TRY:
                try:
                    response_stream = self.client.models.generate_content_stream(
                        model=model_name,
                        contents=full_prompt,
                    )
                    for chunk in response_stream:
                        if chunk.text:
                            yield chunk.text
                    return
                except Exception as e:
                    last_error = e
                    error_text = str(e)
                    # Model retired/unavailable — try the next one in the list.
                    if "404" in error_text or "NOT_FOUND" in error_text:
                        continue
                    # Server temporarily busy — brief retry on the same model.
                    if "503" in error_text or "UNAVAILABLE" in error_text:
                        time.sleep(2)
                        continue
                    raise

            if last_error:
                raise last_error

        except Exception as e:
            error_text = str(e)
            if _is_auth_error(error_text):
                yield (
                    "Chat assistant error: could not authenticate with Gemini. "
                    "Check that GEMINI_API_KEY in .env is current and valid."
                )
            else:
                yield f"Chat assistant error: {error_text}"