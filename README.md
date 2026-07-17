# 🤖 AI Code Review & Security Analysis Agent

An intelligent, multi-agent platform designed to automatically analyze source code (Python and Java) for quality issues, security vulnerabilities, and best-practice violations. 

This project integrates a local **Retrieval-Augmented Generation (RAG)** pipeline to search an offline secure coding knowledge base, providing developers with real-time, highly contextualized tutoring and safe code fixes.

---

## 📌 Problem Statement & Objective

Manual code reviews are slow, subjective, and difficult to scale, leaving critical security risks and quality issues undetected until late in the development lifecycle. 

This agentic platform solves this by acting as an automated "safety gatekeeper." When a developer uploads or pastes their code:
1. **Gatekeeping**: It immediately runs syntax validation checks.
2. **Analysis**: It launches parallel multi-agent diagnostics to dissect code quality issues and OWASP security risks.
3. **Tutoring**: It fetches verified secure-code templates from a local vector library.
4. **Actionable Insights**: It presents an interactive review report with severity scoring alongside a conversational learning chatbot.

---

## 🌟 Key Features

*   **Syntax Validation Gatekeeper**: Instantly checks Python and Java submissions to filter out blank entries, text, or unparseable code before processing.
*   **Multi-Agent Diagnostic Pipeline**: Splits complex analysis tasks among distinct, specialized AI agents to ensure precision and prevent diagnostic overlap.
*   **Offline-First Secure Knowledge Base (RAG)**: Uses an offline vector database (Chroma DB with local embeddings) containing OWASP standards and secure code triads (Insecure -> Flawed -> Clean) to safely tutor developers without sending sensitive code to external cloud environments.
*   **Conversational Assistant**: An interactive chat helper that allows developers to ask follow-up questions to understand structural mistakes or security rules.

---

## 📂 Repository Layout

This project is meticulously organized to isolate backend processes, frontend visualization, and project study documentation:

```text
AI-Code-Review-Security-Analysis/
├── docs/                             <-- Project Study & Design specifications (Milestone 1)
│   ├── system_architecture.md        <-- Details agent roles, system workflow, and analogies
│   └── data_models.md                <-- Outlines structural schemas and data mappings
├── backend/                          <-- Core application logic & AI orchestration
│   ├── knowledge_base/               <-- Local RAG database, ingestion script, and data files
│   │   ├── data/                     <-- Markdown files containing OWASP and clean-code guides
│   │   ├── loaders/                  <-- Custom DocumentLoader parsing local folder paths
│   │   ├── vector_store/             <-- Local SQLite-backed Chroma DB storage
│   │   └── ingest.py                 <-- Database building and indexing script
│   └── submission_module/            <-- Inbound request parser & syntax validator
│       ├── submissions/              <-- Local folder holding past run records
│       ├── validator.py              <-- Code syntax validator (Python AST & Java Parser)
│       ├── storage.py                <-- Handles secure saving/retrieval of submitted files
│       ├── detector.py               <-- Basic structural rules detector
│       ├── main.py                   <-- Orchestrator entry point
│       └── test_submission.py        <-- Local simulation test script
├── frontend/                         <-- Web Interface Assets
│   ├── index.html                    <-- Webpage layout
│   ├── style.css                     <-- Styling and responsive dashboard design
│   └── app.js                        <-- Connection logic between browser and backend API
└── README.md                         <-- This main guide!
📚 Milestone 1 Study Documents
We have created two detailed, highly accessible documents inside the docs/ folder to satisfy the study and design requirements of Milestone 1:

System Architecture Guide:

Features a friendly "Security Checkpoint Team" analogy to explain how our system functions.

Outlines the exact roles, targets, and goals of our 5 AI Agents.

Walks through the step-by-step lifecycle of a code snippet from upload to final report.

Data Models & Schema Guide:

Breaks down technical information packets into easy-to-understand lookup tables.

Defines what a "Code Submission," "Knowledge Base Card," and "Review Finding Alert" look like under the hood.

🚀 How to Build & Run the Knowledge Base
To build and compile your local vector database (Knowledge Base) with the secure-coding rules, use your terminal to run the ingestion sequence:

Step 1: Navigate to the knowledge base folder
Bash
cd backend/knowledge_base
Step 2: Run the indexing script
Bash
python ingest.py
What happens when you run this:
The system opens your .md files inside the data/ directory (OWASP, Code Smells, Best Practices).

The DocumentLoader processes the files and dynamically determines whether they contain Python or Java practices.

The MarkdownChunker cuts the documents into structured pieces.

The LocalEmbedder downloads a lightweight AI math model (~80MB) and transforms text into semantic vectors entirely offline on your machine.

The results are saved securely inside backend/knowledge_base/vector_store/chroma_db.