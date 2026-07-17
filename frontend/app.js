const API_BASE_URL = "http://127.0.0.1:8000";
let activeTab = "pasteTab";
let selectedFile = null;

// ==========================================
// 1. DOM BINDINGS
// ==========================================
const tabButtons = document.querySelectorAll(".tab-btn");
const tabPanels = document.querySelectorAll(".tab-panel");
const pillHighlight = document.getElementById("pillHighlight");
const codePasteArea = document.getElementById("codePasteArea");
const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");
const fileDisplay = document.getElementById("fileDisplay");
const fileInfoText = document.getElementById("fileInfoText");
const removeFileBtn = document.getElementById("removeFileBtn");
const alertBanner = document.getElementById("alertBanner");
const submitBtn = document.getElementById("submitBtn");

const placeholderView = document.getElementById("placeholderView");
const resultsContainer = document.getElementById("resultsContainer");
const diagnosticsHeader = document.getElementById("diagnosticsHeader");
const statusReadout = document.getElementById("statusReadout");
const statusReadoutIcon = document.getElementById("statusReadoutIcon");
const statusReadoutTitle = document.getElementById("statusReadoutTitle");
const statusReadoutSub = document.getElementById("statusReadoutSub");
const resLanguage = document.getElementById("resLanguage");
const resSourceType = document.getElementById("resSourceType");

const ICON_VALID = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
const ICON_INVALID = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
const ICON_UNKNOWN = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';

// ==========================================
// 2. TAB NAVIGATION
// ==========================================
tabButtons.forEach((button, index) => {
    button.addEventListener("click", (e) => {
        e.preventDefault();
        const targetTab = button.getAttribute("data-tab");
        tabButtons.forEach(btn => btn.classList.remove("active"));
        tabPanels.forEach(panel => panel.classList.remove("active"));
        button.classList.add("active");
        document.getElementById(targetTab).classList.add("active");
        activeTab = targetTab;
        pillHighlight.style.transform = `translateX(${index * 100}%)`;
        hideAlert();
    });
});

// ==========================================
// 3. FILE INGESTION
// ==========================================
dropZone.addEventListener("click", () => fileInput.click());
dropZone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        fileInput.click();
    }
});

fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
        handleFileSelection(e.target.files[0]);
    }
});

dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "var(--accent-teal-line)";
});

dropZone.addEventListener("dragleave", () => {
    dropZone.style.borderColor = "";
});

dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "";
    if (e.dataTransfer.files.length > 0) {
        handleFileSelection(e.dataTransfer.files[0]);
    }
});

function handleFileSelection(file) {
    const extension = file.name.split('.').pop().toLowerCase();
    if (extension !== 'py' && extension !== 'java') {
        showAlert("Unsupported file type. Upload a .py or .java file.");
        return;
    }
    selectedFile = file;
    fileInfoText.textContent = `${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
    dropZone.style.display = "none";
    fileDisplay.style.display = "flex";
    hideAlert();
}

removeFileBtn.addEventListener("click", () => {
    selectedFile = null;
    fileInput.value = "";
    fileDisplay.style.display = "none";
    dropZone.style.display = "flex";
});

// ==========================================
// 4. SUBMIT & ANALYZE
// ==========================================
submitBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    hideAlert();

    if (activeTab === "pasteTab") {
        const code = codePasteArea.value.trim();
        if (!code) {
            showAlert("Paste some code before running analysis.");
            return;
        }

        try {
            setLoading(true);
            const response = await fetch(`${API_BASE_URL}/submit/paste`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code })
            });
            const data = await response.json();
            renderDiagnostics(data);
        } catch (err) {
            showAlert("Couldn't reach the analysis service. Check that it's running.");
        } finally {
            setLoading(false);
        }
    } else {
        if (!selectedFile) {
            showAlert("Upload a file before running analysis.");
            return;
        }

        const formData = new FormData();
        formData.append("file", selectedFile);

        try {
            setLoading(true);
            const response = await fetch(`${API_BASE_URL}/submit/upload`, {
                method: "POST",
                body: formData
            });
            const data = await response.json();
            renderDiagnostics(data);
        } catch (err) {
            showAlert("File upload failed. Check your connection and try again.");
        } finally {
            setLoading(false);
        }
    }
});

// ==========================================
// 5. DIAGNOSTICS RENDER
// ==========================================
function renderDiagnostics(data) {
    placeholderView.style.display = "none";
    resultsContainer.style.display = "block";

    const isSuccess = data.status === "success";
    const language = data.submission?.language || data.detected_language || null;
    const sourceType = data.submission?.source_type || (activeTab === "pasteTab" ? "paste" : "upload");

    resLanguage.textContent = language ? language.toUpperCase() : "UNKNOWN";
    resSourceType.textContent = sourceType.toUpperCase();

    statusReadout.classList.remove("is-valid", "is-invalid", "is-unknown");

    if (isSuccess) {
        statusReadout.classList.add("is-valid");
        statusReadoutIcon.innerHTML = ICON_VALID;
        statusReadoutTitle.textContent = "No syntax errors found";
        statusReadoutSub.textContent = data.message || "This submission compiled with no errors.";
    } else if (language) {
        statusReadout.classList.add("is-invalid");
        statusReadoutIcon.innerHTML = ICON_INVALID;
        statusReadoutTitle.textContent = "Syntax error detected";
        statusReadoutSub.textContent = data.message || "This submission did not pass validation.";
    } else {
        statusReadout.classList.add("is-unknown");
        statusReadoutIcon.innerHTML = ICON_UNKNOWN;
        statusReadoutTitle.textContent = "Language not recognized";
        statusReadoutSub.textContent = data.message || "Only Python and Java are supported.";
    }
}

function setLoading(isLoading) {
    if (isLoading) {
        submitBtn.disabled = true;
        submitBtn.querySelector(".btn-text").textContent = "Running analysis...";
        diagnosticsHeader.classList.add("scanning");
    } else {
        submitBtn.disabled = false;
        submitBtn.querySelector(".btn-text").textContent = "Run analysis";
        diagnosticsHeader.classList.remove("scanning");
    }
}

function showAlert(message) {
    alertBanner.textContent = message;
    alertBanner.style.display = "block";
}

function hideAlert() {
    alertBanner.style.display = "none";
}