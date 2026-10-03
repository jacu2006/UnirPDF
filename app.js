/**
 * UniPDF – app.js
 * Merges multiple PDFs in-browser using pdf-lib (no server upload).
 *
 * Security notes:
 * - All file handling is local (FileReader API) – no network requests.
 * - DOM manipulation uses textContent / createElement / setAttribute only (no innerHTML).
 * - File type validated by MIME type AND magic bytes (PDF header %PDF-).
 * - File size capped at 50 MB per file to prevent DoS / memory exhaustion.
 * - Filenames are sanitised before display (textContent, not innerHTML).
 * TODO(security): Add antivirus/CDR scanning if deploying in a server context.
 * TODO(security): Consider OAuth if a login layer is ever added.
 */

'use strict';

// ── Constants ────────────────────────────────────────────────────────────────
const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB per file
const ALLOWED_MIME_TYPE   = 'application/pdf';
const PDF_MAGIC_BYTES     = '%PDF-';           // first 5 bytes of a valid PDF

// ── State ────────────────────────────────────────────────────────────────────
let files    = [];       // Array<File>  – ordered list of PDFs to merge
let mergedBytes = null;  // Uint8Array   – result of last merge
let dragSrcIdx  = null;  // index of item being dragged

// ── DOM refs ─────────────────────────────────────────────────────────────────
const dropzoneSection  = document.getElementById('dropzoneSection');
const dropzone         = document.getElementById('dropzone');
const browseBtn        = document.getElementById('browseBtn');
const fileInput        = document.getElementById('fileInput');

const filelistSection  = document.getElementById('filelistSection');
const fileCountBadge   = document.getElementById('fileCount');
const addMoreBtn       = document.getElementById('addMoreBtn');
const clearAllBtn      = document.getElementById('clearAllBtn');
const fileList         = document.getElementById('fileList');
const mergeBtn         = document.getElementById('mergeBtn');

const progressWrapper  = document.getElementById('progressWrapper');
const progressBar      = document.getElementById('progressBar');
const progressText     = document.getElementById('progressText');

const successCard      = document.getElementById('successCard');
const successInfo      = document.getElementById('successInfo');
const downloadBtn      = document.getElementById('downloadBtn');
const newMergeBtn      = document.getElementById('newMergeBtn');

const errorCard        = document.getElementById('errorCard');
const errorMsg         = document.getElementById('errorMsg');
const errorRetryBtn    = document.getElementById('errorRetryBtn');

// ── Utility helpers ───────────────────────────────────────────────────────────

/** Format bytes to human-readable string */
function formatBytes(bytes) {
  if (bytes < 1024)        return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

/** Sanitise a filename for safe display (returns a plain string) */
function sanitiseName(name) {
  // Strip any path components – only keep the basename
  return String(name).replace(/[/\\]/g, '_').slice(0, 200);
}

/** Show/hide an element (using hidden attribute) */
function show(el) { el.hidden = false; }
function hide(el) { el.hidden = true;  }

/** Read the first bytes of a File to verify PDF magic bytes */
function verifyPDFMagicBytes(file) {
  return new Promise((resolve) => {
    const slice  = file.slice(0, 5);
    const reader = new FileReader();
    reader.onload = (e) => {
      const header = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(e.target.result));
      resolve(header.startsWith(PDF_MAGIC_BYTES));
    };
    reader.onerror = () => resolve(false);
    reader.readAsArrayBuffer(slice);
  });
}

/** Read a File as ArrayBuffer (promise wrapper) */
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = (e) => resolve(e.target.result);
    reader.onerror = ()  => reject(new Error(`No se pudo leer: ${sanitiseName(file.name)}`));
    reader.readAsArrayBuffer(file);
  });
}

// ── File validation ───────────────────────────────────────────────────────────

async function validateFile(file) {
  if (file.type !== ALLOWED_MIME_TYPE && !file.name.toLowerCase().endsWith('.pdf')) {
    return { ok: false, reason: `"${sanitiseName(file.name)}" no es un PDF.` };
  }
  if (file.size > MAX_FILE_SIZE_BYTES) {
    return { ok: false, reason: `"${sanitiseName(file.name)}" supera el límite de 50 MB.` };
  }
  const magicOk = await verifyPDFMagicBytes(file);
  if (!magicOk) {
    return { ok: false, reason: `"${sanitiseName(file.name)}" no parece ser un PDF válido.` };
  }
  return { ok: true };
}

// ── File ingestion ────────────────────────────────────────────────────────────

async function addFiles(newFiles) {
  const toAdd = [];
  const errors = [];

  for (const file of newFiles) {
    // Skip duplicates (same name + same size)
    const isDuplicate = files.some(f => f.name === file.name && f.size === file.size);
    if (isDuplicate) continue;

    const result = await validateFile(file);
    if (result.ok) {
      toAdd.push(file);
    } else {
      errors.push(result.reason);
    }
  }

  if (errors.length) {
    showError(errors.join('\n'));
  }

  if (toAdd.length) {
    files = [...files, ...toAdd];
    renderFileList();
    showFileListSection();
  }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

function renderFileList() {
  // Clear list safely
  fileList.replaceChildren();
  fileCountBadge.textContent = String(files.length);

  files.forEach((file, idx) => {
    const li = buildFileItem(file, idx);
    fileList.appendChild(li);
  });
}

function buildFileItem(file, idx) {
  const li = document.createElement('li');
  li.className = 'file-item';
  li.setAttribute('draggable', 'true');
  li.dataset.idx = String(idx);

  // Drag handle
  const handle = document.createElement('span');
  handle.className = 'drag-handle';
  handle.setAttribute('aria-hidden', 'true');
  handle.setAttribute('title', 'Arrastra para reordenar');
  const handleSvg = buildDragHandleSvg();
  handle.appendChild(handleSvg);

  // PDF icon
  const iconWrap = document.createElement('span');
  iconWrap.className = 'file-pdf-icon';
  iconWrap.setAttribute('aria-hidden', 'true');
  iconWrap.appendChild(buildPdfIconSvg());

  // Info
  const info = document.createElement('div');
  info.className = 'file-info';

  const namePara = document.createElement('p');
  namePara.className = 'file-name';
  namePara.textContent = sanitiseName(file.name);  // safe: textContent, not innerHTML

  const metaPara = document.createElement('p');
  metaPara.className = 'file-meta';
  metaPara.textContent = formatBytes(file.size);

  info.appendChild(namePara);
  info.appendChild(metaPara);

  // Order badge
  const orderBadge = document.createElement('span');
  orderBadge.className = 'file-order';
  orderBadge.textContent = String(idx + 1);
  orderBadge.setAttribute('aria-label', `Posición ${idx + 1}`);

  // Remove button
  const removeBtn = document.createElement('button');
  removeBtn.className = 'file-remove-btn';
  removeBtn.setAttribute('type', 'button');
  removeBtn.setAttribute('aria-label', `Eliminar ${sanitiseName(file.name)}`);
  const removeSvg = buildRemoveSvg();
  removeBtn.appendChild(removeSvg);
  removeBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    removeFile(idx);
  });

  li.appendChild(handle);
  li.appendChild(iconWrap);
  li.appendChild(info);
  li.appendChild(orderBadge);
  li.appendChild(removeBtn);

  // Drag events
  li.addEventListener('dragstart', onDragStart);
  li.addEventListener('dragover',  onDragOver);
  li.addEventListener('dragleave', onDragLeave);
  li.addEventListener('drop',      onDrop);
  li.addEventListener('dragend',   onDragEnd);

  return li;
}

// SVG builders (use DOMParser for complex SVGs to avoid innerHTML)
function buildDragHandleSvg() {
  const parser = new DOMParser();
  const doc = parser.parseFromString(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">' +
      '<circle cx="9" cy="6"  r="1.5" fill="currentColor"/>' +
      '<circle cx="9" cy="12" r="1.5" fill="currentColor"/>' +
      '<circle cx="9" cy="18" r="1.5" fill="currentColor"/>' +
      '<circle cx="15" cy="6"  r="1.5" fill="currentColor"/>' +
      '<circle cx="15" cy="12" r="1.5" fill="currentColor"/>' +
      '<circle cx="15" cy="18" r="1.5" fill="currentColor"/>' +
    '</svg>',
    'image/svg+xml'
  );
  return doc.documentElement;
}

function buildPdfIconSvg() {
  const parser = new DOMParser();
  const doc = parser.parseFromString(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">' +
      '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>' +
      '<path d="M14 2v6h6" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>' +
      '<path d="M9 13h6M9 17h4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>' +
    '</svg>',
    'image/svg+xml'
  );
  return doc.documentElement;
}

function buildRemoveSvg() {
  const parser = new DOMParser();
  const doc = parser.parseFromString(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">' +
      '<path d="M18 6L6 18M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' +
    '</svg>',
    'image/svg+xml'
  );
  return doc.documentElement;
}

// ── State transitions ─────────────────────────────────────────────────────────

function showFileListSection() {
  hide(dropzoneSection);
  show(filelistSection);
  hide(progressWrapper);
  hide(successCard);
  hide(errorCard);
}

function showDropzone() {
  show(dropzoneSection);
  hide(filelistSection);
  hide(progressWrapper);
  hide(successCard);
  hide(errorCard);
}

function showProgress(text = 'Procesando…') {
  hide(filelistSection);
  hide(successCard);
  hide(errorCard);
  progressBar.style.width = '0%';
  progressText.textContent = text;
  show(progressWrapper);
}

function setProgress(pct, text) {
  progressBar.style.width = Math.min(100, pct) + '%';
  if (text) progressText.textContent = text;
}

function showSuccess(info) {
  hide(progressWrapper);
  hide(filelistSection);
  hide(errorCard);
  successInfo.textContent = info;   // safe: textContent
  show(successCard);
}

function showError(msg) {
  hide(progressWrapper);
  errorMsg.textContent = msg;       // safe: textContent
  show(errorCard);
}

// ── Remove / clear ────────────────────────────────────────────────────────────

function removeFile(idx) {
  files.splice(idx, 1);
  if (files.length === 0) {
    showDropzone();
    fileInput.value = '';
  } else {
    renderFileList();
  }
}

function clearAll() {
  files = [];
  mergedBytes = null;
  fileInput.value = '';
  showDropzone();
}

// ── Drag-and-drop reorder ─────────────────────────────────────────────────────

function onDragStart(e) {
  dragSrcIdx = Number(this.dataset.idx);
  this.classList.add('dragging');
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', String(dragSrcIdx)); // required by Firefox
}

function onDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  this.classList.add('drag-target');
}

function onDragLeave() {
  this.classList.remove('drag-target');
}

function onDrop(e) {
  e.preventDefault();
  this.classList.remove('drag-target');
  const targetIdx = Number(this.dataset.idx);
  if (dragSrcIdx === null || dragSrcIdx === targetIdx) return;

  const moved = files.splice(dragSrcIdx, 1)[0];
  files.splice(targetIdx, 0, moved);
  renderFileList();
}

function onDragEnd() {
  this.classList.remove('dragging');
  dragSrcIdx = null;
  document.querySelectorAll('.file-item').forEach(el => el.classList.remove('drag-target'));
}

// ── Drop zone (file drag from OS) ─────────────────────────────────────────────

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('drag-over');
});

dropzone.addEventListener('dragleave', (e) => {
  if (!dropzone.contains(e.relatedTarget)) {
    dropzone.classList.remove('drag-over');
  }
});

dropzone.addEventListener('drop', async (e) => {
  e.preventDefault();
  dropzone.classList.remove('drag-over');
  const droppedFiles = Array.from(e.dataTransfer.files);
  await addFiles(droppedFiles);
});

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
});

browseBtn.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });

fileInput.addEventListener('change', async () => {
  await addFiles(Array.from(fileInput.files));
  fileInput.value = ''; // reset so same files can be re-added after removal
});

addMoreBtn.addEventListener('click', () => fileInput.click());
clearAllBtn.addEventListener('click', clearAll);

newMergeBtn.addEventListener('click', () => {
  mergedBytes = null;
  clearAll();
});

errorRetryBtn.addEventListener('click', () => {
  hide(errorCard);
  if (files.length) showFileListSection();
  else showDropzone();
});

// ── PDF Merge ─────────────────────────────────────────────────────────────────

mergeBtn.addEventListener('click', mergePDFs);

async function mergePDFs() {
  if (files.length < 2) {
    showError('Necesitas al menos 2 archivos PDF para unirlos.');
    return;
  }

  showProgress('Iniciando…');
  mergedBytes = null;

  try {
    const { PDFDocument } = PDFLib;
    const mergedDoc = await PDFDocument.create();

    let totalPages = 0;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const pct  = Math.round(((i) / files.length) * 85);
      setProgress(pct, `Procesando ${i + 1} de ${files.length}: ${sanitiseName(file.name)}`);

      let arrayBuffer;
      try {
        arrayBuffer = await readFileAsArrayBuffer(file);
      } catch {
        throw new Error(`No se pudo leer el archivo "${sanitiseName(file.name)}".`);
      }

      let srcDoc;
      try {
        srcDoc = await PDFDocument.load(arrayBuffer, { ignoreEncryption: false });
      } catch {
        throw new Error(`El archivo "${sanitiseName(file.name)}" está dañado, cifrado o no es un PDF válido.`);
      }

      const pages = await mergedDoc.copyPages(srcDoc, srcDoc.getPageIndices());
      pages.forEach((page) => mergedDoc.addPage(page));
      totalPages += pages.length;
    }

    setProgress(92, 'Generando PDF final…');
    const pdfBytes = await mergedDoc.save();
    mergedBytes = pdfBytes;

    setProgress(100, '¡Listo!');

    const totalSize = formatBytes(pdfBytes.byteLength);
    showSuccess(`${files.length} archivos · ${totalPages} páginas · ${totalSize}`);

  } catch (err) {
    // Log for developer; generic message to user
    console.error('[UniPDF] merge error:', err);
    showError(err.message || 'Ocurrió un error al unir los PDFs. Revisa que todos los archivos sean PDFs válidos.');
    show(filelistSection);
  }
}

// ── Download ──────────────────────────────────────────────────────────────────

downloadBtn.addEventListener('click', () => {
  if (!mergedBytes) return;

  const blob = new Blob([mergedBytes], { type: 'application/pdf' });
  const url  = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href     = url;
  a.download = 'documento_unido.pdf';
  // Do not append to DOM (avoids any XSS surface); direct click is safe
  a.click();

  // Revoke after small delay to allow download to start
  setTimeout(() => URL.revokeObjectURL(url), 5000);
});
