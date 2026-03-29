const wasmStatus = document.getElementById("wasmStatus");
const runtimeLog = document.getElementById("runtimeLog");
const queueSummary = document.getElementById("queueSummary");
const fileInput = document.getElementById("fileInput");
const dropzone = document.getElementById("dropzone");
const resultsSection = document.getElementById("results");
const resultList = document.getElementById("resultList");

let wasmReady = false;
const recoveredFiles = new Map();

function log(message, kind = "info") {
  if (runtimeLog) {
    runtimeLog.textContent += `\n${message}`;
  }
  if (wasmStatus) {
    wasmStatus.textContent = message;
    wasmStatus.className = `status ${kind}`;
  }
}

function createDownloadButton(id, filename, label = "Download recovered file") {
  const button = document.createElement("button");
  button.textContent = label;
  button.addEventListener("click", () => {
    const bytes = recoveredFiles.get(id);
    if (!bytes) return;

    const blob = new Blob([bytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });
  return button;
}

function baseName(name) {
  const dot = name.lastIndexOf(".");
  if (dot <= 0) {
    return name;
  }
  return name.slice(0, dot);
}

function extensionForDetectedType(type) {
  switch (type) {
    case "PDF":
      return ".pdf";
    case "JPEG":
      return ".jpg";
    case "PNG":
      return ".png";
    case "ZIP/DOCX/XLSX":
      return ".zip";
    case "OLE2/DOC/XLS":
      return ".ole";
    case "XML/HTML":
      return ".xml";
    case "JSON":
      return ".json";
    default:
      return ".bin";
  }
}

function downloadName(name, detectedType) {
  return `${baseName(name)}${extensionForDetectedType(detectedType)}`;
}

function downloadLabel(detectedType) {
  if (!detectedType || detectedType === "unknown") {
    return "Download recovered file";
  }
  return `Download ${detectedType}`;
}

function renderResultCard(file, analysis, decompressResult) {
  const card = document.createElement("article");
  card.className = "result-card";

  const ok = !decompressResult.error;
  const outputName = downloadName(file.name, decompressResult.detectedType);
  const tagClass = ok ? "ok" : "error";
  const tagText = ok ? "decompressed" : "failed";

  card.innerHTML = `
    <div class="result-header">
      <div>
        <h3 class="file-name">${file.name}</h3>
        <div class="small">${file.size} bytes</div>
      </div>
      <span class="tag ${tagClass}">${tagText}</span>
    </div>
    <pre>${ok ?
      `Algorithm: ${analysis.algorithmName}\nExpected original size: ${analysis.uncompressedSize} bytes\nEntropy: ${analysis.entropy.toFixed(4)} bits/byte\nNonsense bits: ${analysis.nonsenseBits}\nDetected type: ${decompressResult.detectedType}\nMD5: ${decompressResult.md5}`
      : `Error: ${decompressResult.error}`}</pre>
  `;

  if (ok) {
    recoveredFiles.set(file.name, decompressResult.data);
    const actions = document.createElement("div");
    actions.className = "result-actions";
    actions.appendChild(createDownloadButton(file.name, outputName, downloadLabel(decompressResult.detectedType)));
    card.appendChild(actions);
  }

  return card;
}

async function processFile(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const analysis = globalThis.sapAnalyze(bytes);
  const decompressed = globalThis.sapDecompress(bytes);

  if (!decompressed.error) {
    decompressed.detectedType = globalThis.sapDetectType(decompressed.data);
  }

  resultList.appendChild(renderResultCard(file, analysis, decompressed));
}

async function processFiles(files) {
  if (!files.length) {
    return;
  }

  if (!wasmReady) {
    log("WebAssembly runtime is not ready yet.", "warn");
    return;
  }

  resultsSection.style.display = "block";
  queueSummary.textContent = `Processing ${files.length} file(s) sequentially.`;
  runtimeLog.textContent = "Ready.";
  resultList.innerHTML = "";

  for (const file of files) {
    log(`Processing ${file.name} ...`);
    await processFile(file);
  }

  queueSummary.textContent = `Finished processing ${files.length} file(s).`;
  log("Done.", "ok");
}

async function initWasm() {
  try {
    const go = new Go();
    const result = await WebAssembly.instantiateStreaming(fetch("sapblob.wasm"), go.importObject);
    go.run(result.instance);
    wasmReady = true;
    log("Go WebAssembly runtime ready. Files stay in your browser.", "ok");
  } catch (error) {
    log(`Failed to initialize WebAssembly runtime: ${error}`, "error");
  }
}

if (dropzone && fileInput) {
  dropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => processFiles([...fileInput.files]));

  ["dragenter", "dragover"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", (event) => {
    const files = [...event.dataTransfer.files];
    processFiles(files);
  });
}

initWasm();
