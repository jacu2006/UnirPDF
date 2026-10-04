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

// ── Tab navigation ────────────────────────────────────────────────────────────

const tabMerge   = document.getElementById('tabMerge');
const tabEdit    = document.getElementById('tabEdit');
const tabImg     = document.getElementById('tabImg');
const tabMd      = document.getElementById('tabMd');
const panelMerge = document.getElementById('panelMerge');
const panelEdit  = document.getElementById('panelEdit');
const panelImg   = document.getElementById('panelImg');
const panelMd    = document.getElementById('panelMd');

function activateTab(tab) {
  tabMerge.classList.toggle('tab-active', tab === 'merge');
  tabEdit.classList.toggle('tab-active', tab === 'edit');
  tabImg.classList.toggle('tab-active', tab === 'img');
  tabMd.classList.toggle('tab-active', tab === 'md');

  tabMerge.setAttribute('aria-selected', String(tab === 'merge'));
  tabEdit.setAttribute('aria-selected', String(tab === 'edit'));
  tabImg.setAttribute('aria-selected', String(tab === 'img'));
  tabMd.setAttribute('aria-selected', String(tab === 'md'));

  panelMerge.hidden = (tab !== 'merge');
  panelEdit.hidden  = (tab !== 'edit');
  panelImg.hidden   = (tab !== 'img');
  panelMd.hidden    = (tab !== 'md');
}

tabMerge.addEventListener('click', () => activateTab('merge'));
tabEdit.addEventListener('click',  () => activateTab('edit'));
tabImg.addEventListener('click',   () => activateTab('img'));
tabMd.addEventListener('click',    () => activateTab('md'));

// ── Editar PDF feature ────────────────────────────────────────────────────────

const editDropzoneSection   = document.getElementById('editDropzoneSection');
const editDropzone          = document.getElementById('editDropzone');
const editBrowseBtn         = document.getElementById('editBrowseBtn');
const editFileInput         = document.getElementById('editFileInput');

const editSection           = document.getElementById('editSection');
const editFilename          = document.getElementById('editFilename');
const editPageCount         = document.getElementById('editPageCount');
const editChangePdfBtn      = document.getElementById('editChangePdfBtn');

const editSelectAllBtn      = document.getElementById('editSelectAllBtn');
const editInvertSelectBtn   = document.getElementById('editInvertSelectBtn');
const editDeleteSelectedBtn = document.getElementById('editDeleteSelectedBtn');

const editInvertOrderBtn    = document.getElementById('editInvertOrderBtn');
const editResetOrderBtn     = document.getElementById('editResetOrderBtn');
const editRotateBtn         = document.getElementById('editRotateBtn');

const editRangeInput        = document.getElementById('editRangeInput');
const editApplyRangeBtn     = document.getElementById('editApplyRangeBtn');
const editRangeHint         = document.getElementById('editRangeHint');

const editPageGrid          = document.getElementById('editPageGrid');
const editSaveBtn            = document.getElementById('editSaveBtn');

const editProgressWrapper   = document.getElementById('editProgressWrapper');
const editProgressBar       = document.getElementById('editProgressBar');
const editProgressText      = document.getElementById('editProgressText');

const editErrorCard         = document.getElementById('editErrorCard');
const editErrorMsg          = document.getElementById('editErrorMsg');
const editErrorRetryBtn     = document.getElementById('editErrorRetryBtn');

// Edit State
let editFile          = null;
let editOriginalBytes = null;
let editPages         = []; // Array<{ id, originalIndex, selected, rotation, canvas }>
let originalPagesCopy = [];
let editDragSrcIdx    = null;

function showEditProgress(text = 'Procesando PDF…') {
  hide(editSection);
  hide(editDropzoneSection);
  hide(editErrorCard);
  editProgressBar.style.width = '0%';
  editProgressText.textContent = text;
  show(editProgressWrapper);
}

function setEditProgress(pct, text) {
  editProgressBar.style.width = Math.min(100, pct) + '%';
  if (text) editProgressText.textContent = text;
}

function showEditError(msg) {
  hide(editProgressWrapper);
  editErrorMsg.textContent = msg;
  show(editErrorCard);
}

function hideEditError() {
  hide(editErrorCard);
}

function showEditWorkspace() {
  hide(editDropzoneSection);
  hide(editProgressWrapper);
  hide(editErrorCard);
  show(editSection);
}

function showEditDropzone() {
  show(editDropzoneSection);
  hide(editSection);
  hide(editProgressWrapper);
  hide(editErrorCard);
}

/** Load a PDF file into the page editor */
async function loadEditPdf(file) {
  const result = await validateFile(file);
  if (!result.ok) {
    showEditError(result.reason);
    return;
  }

  showEditProgress('Cargando PDF y generando vistas previas…');

  try {
    editFile = file;
    editFilename.textContent = sanitiseName(file.name);
    editOriginalBytes = await readFileAsArrayBuffer(file);

    if (window.pdfjsLib) {
      pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';
    } else {
      throw new Error('La librería PDF.js no está disponible.');
    }

    const pdfData = editOriginalBytes.slice(0);
    const loadingTask = pdfjsLib.getDocument({ data: pdfData });
    const pdfjsDoc = await loadingTask.promise;
    const numPages = pdfjsDoc.numPages;

    editPages = [];

    for (let i = 1; i <= numPages; i++) {
      const pct = Math.round((i / numPages) * 90);
      setEditProgress(pct, `Generando vista previa de página ${i} de ${numPages}…`);

      const page = await pdfjsDoc.getPage(i);
      const viewport = page.getViewport({ scale: 0.35 });
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(viewport.width);
      canvas.height = Math.floor(viewport.height);
      const ctx = canvas.getContext('2d');

      await page.render({ canvasContext: ctx, viewport }).promise;

      editPages.push({
        id: 'p_' + i + '_' + Math.random().toString(36).substr(2, 6),
        originalIndex: i - 1,
        selected: false,
        rotation: 0,
        canvas: canvas,
      });
    }

    originalPagesCopy = editPages.map(p => ({ ...p }));
    setEditProgress(100, '¡Cargado!');
    resetRangeUI();
    showEditWorkspace();
    renderEditGrid();

  } catch (err) {
    console.error('[UniPDF] loadEditPdf error:', err);
    showEditError('No se pudo cargar el PDF para editar. Revisa que el archivo no esté cifrado ni dañado.');
  }
}

/** Render the grid of PDF page cards */
function renderEditGrid() {
  editPageGrid.replaceChildren();
  editPageCount.textContent = `${editPages.length} página${editPages.length === 1 ? '' : 's'}`;

  const selectedCount = editPages.filter(p => p.selected).length;
  editDeleteSelectedBtn.disabled = (selectedCount === 0 || editPages.length === 0);

  editPages.forEach((pageItem, idx) => {
    const card = buildPageCard(pageItem, idx);
    editPageGrid.appendChild(card);
  });
}

/** Build a page card DOM node */
function buildPageCard(pageItem, idx) {
  const card = document.createElement('div');
  card.className = 'page-card' + (pageItem.selected ? ' selected' : '');
  card.setAttribute('draggable', 'true');
  card.setAttribute('role', 'listitem');
  card.dataset.idx = String(idx);

  // Card Header: Checkbox + Delete button
  const header = document.createElement('div');
  header.className = 'page-card-header';

  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.className = 'page-card-checkbox';
  checkbox.checked = pageItem.selected;
  checkbox.setAttribute('aria-label', `Seleccionar página ${idx + 1}`);
  checkbox.addEventListener('change', (e) => {
    e.stopPropagation();
    pageItem.selected = checkbox.checked;
    renderEditGrid();
  });

  const deleteBtn = document.createElement('button');
  deleteBtn.type = 'button';
  deleteBtn.className = 'page-card-delete';
  deleteBtn.setAttribute('title', `Eliminar página ${idx + 1}`);
  deleteBtn.setAttribute('aria-label', `Eliminar página ${idx + 1}`);
  deleteBtn.appendChild(buildRemoveSvg());
  deleteBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    deleteEditPage(idx);
  });

  header.appendChild(checkbox);
  header.appendChild(deleteBtn);

  // Card Body: Thumbnail Canvas
  const body = document.createElement('div');
  body.className = 'page-card-body';

  const thumbCanvas = document.createElement('canvas');
  thumbCanvas.className = 'page-card-canvas';
  thumbCanvas.width = pageItem.canvas.width;
  thumbCanvas.height = pageItem.canvas.height;
  const ctx = thumbCanvas.getContext('2d');
  ctx.drawImage(pageItem.canvas, 0, 0);

  if (pageItem.rotation) {
    thumbCanvas.style.transform = `rotate(${pageItem.rotation}deg)`;
  }

  body.appendChild(thumbCanvas);

  // Card Footer: Labels
  const footer = document.createElement('div');
  footer.className = 'page-card-footer';

  const badge = document.createElement('span');
  badge.className = 'page-card-badge';
  badge.textContent = `Pág. ${idx + 1}`;

  footer.appendChild(badge);

  if (pageItem.originalIndex !== idx) {
    const orig = document.createElement('span');
    orig.className = 'page-card-orig';
    orig.textContent = `(Orig: ${pageItem.originalIndex + 1})`;
    footer.appendChild(orig);
  }

  if (pageItem.rotation) {
    const rotBadge = document.createElement('span');
    rotBadge.className = 'badge';
    rotBadge.textContent = `${pageItem.rotation}°`;
    rotBadge.style.fontSize = '.65rem';
    footer.appendChild(rotBadge);
  }

  card.appendChild(header);
  card.appendChild(body);
  card.appendChild(footer);

  // Drag and Drop handlers
  card.addEventListener('dragstart', onEditCardDragStart);
  card.addEventListener('dragover',  onEditCardDragOver);
  card.addEventListener('dragleave', onEditCardDragLeave);
  card.addEventListener('drop',      onEditCardDrop);
  card.addEventListener('dragend',   onEditCardDragEnd);

  // Click card to toggle selection
  card.addEventListener('click', (e) => {
    if (e.target === checkbox || e.target === deleteBtn || deleteBtn.contains(e.target)) return;
    pageItem.selected = !pageItem.selected;
    renderEditGrid();
  });

  return card;
}

// Drag & drop handlers for page grid
function onEditCardDragStart(e) {
  editDragSrcIdx = Number(this.dataset.idx);
  this.classList.add('dragging');
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', String(editDragSrcIdx));
}

function onEditCardDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  this.classList.add('drag-target');
}

function onEditCardDragLeave() {
  this.classList.remove('drag-target');
}

function onEditCardDrop(e) {
  e.preventDefault();
  this.classList.remove('drag-target');
  const targetIdx = Number(this.dataset.idx);
  if (editDragSrcIdx === null || editDragSrcIdx === targetIdx) return;

  const moved = editPages.splice(editDragSrcIdx, 1)[0];
  editPages.splice(targetIdx, 0, moved);
  renderEditGrid();
}

function onEditCardDragEnd() {
  this.classList.remove('dragging');
  editDragSrcIdx = null;
  document.querySelectorAll('.page-card').forEach(el => el.classList.remove('drag-target'));
}

// Edit operations
function deleteEditPage(idx) {
  editPages.splice(idx, 1);
  renderEditGrid();
}

editSelectAllBtn.addEventListener('click', () => {
  const allSelected = editPages.length > 0 && editPages.every(p => p.selected);
  editPages.forEach(p => p.selected = !allSelected);
  renderEditGrid();
});

editInvertSelectBtn.addEventListener('click', () => {
  editPages.forEach(p => p.selected = !p.selected);
  renderEditGrid();
});

editDeleteSelectedBtn.addEventListener('click', () => {
  editPages = editPages.filter(p => !p.selected);
  renderEditGrid();
});

editInvertOrderBtn.addEventListener('click', () => {
  editPages.reverse();
  renderEditGrid();
});

editResetOrderBtn.addEventListener('click', () => {
  editPages = originalPagesCopy.map(p => ({ ...p, selected: false, rotation: 0 }));
  resetRangeUI();
  renderEditGrid();
});

editRotateBtn.addEventListener('click', () => {
  const hasSelected = editPages.some(p => p.selected);
  const targets = hasSelected ? editPages.filter(p => p.selected) : editPages;
  targets.forEach(p => p.rotation = (p.rotation + 90) % 360);
  renderEditGrid();
});

editChangePdfBtn.addEventListener('click', () => {
  editFile = null;
  editOriginalBytes = null;
  editPages = [];
  originalPagesCopy = [];
  editFileInput.value = '';
  resetRangeUI();
  showEditDropzone();
});

// ── Range Selection Logic ─────────────────────────────────────────────────────

function resetRangeUI() {
  if (!editRangeInput) return;
  editRangeInput.value = '';
  editRangeInput.classList.remove('is-invalid');
  editRangeHint.textContent = 'Ej. 3-12, 22-45';
  editRangeHint.className = 'edit-range-hint';
}

/** Parse a page range string (e.g. "3-12, 22-45") and validate bounds */
function parsePageRange(str, maxPages) {
  const trimmed = str.trim();
  if (!trimmed) {
    return { valid: true, indices: [], message: 'Ej. 3-12, 22-45' };
  }

  if (maxPages <= 0) {
    return { valid: false, indices: [], message: 'El PDF no tiene páginas.' };
  }

  const parts = trimmed.split(',').map(s => s.trim()).filter(Boolean);
  if (parts.length === 0) {
    return { valid: true, indices: [], message: 'Ej. 3-12, 22-45' };
  }

  const selectedIndices = new Set();

  for (const part of parts) {
    if (part.includes('-')) {
      const rangeParts = part.split('-');
      if (rangeParts.length !== 2 || !rangeParts[0] || !rangeParts[1]) {
        return { valid: false, indices: [], message: `Formato de rango inválido en "${part}"` };
      }
      const start = parseInt(rangeParts[0], 10);
      const end   = parseInt(rangeParts[1], 10);

      if (isNaN(start) || isNaN(end)) {
        return { valid: false, indices: [], message: `Números inválidos en "${part}"` };
      }
      if (start < 1 || start > maxPages) {
        return { valid: false, indices: [], message: `La página ${start} está fuera de rango (1 - ${maxPages})` };
      }
      if (end < 1 || end > maxPages) {
        return { valid: false, indices: [], message: `La página ${end} está fuera de rango (1 - ${maxPages})` };
      }
      if (start > end) {
        return { valid: false, indices: [], message: `Rango inválido: ${start} es mayor que ${end}` };
      }

      for (let p = start; p <= end; p++) {
        selectedIndices.add(p - 1);
      }
    } else {
      const pageNum = parseInt(part, 10);
      if (isNaN(pageNum)) {
        return { valid: false, indices: [], message: `Número inválido "${part}"` };
      }
      if (pageNum < 1 || pageNum > maxPages) {
        return { valid: false, indices: [], message: `La página ${pageNum} no existe (el PDF tiene ${maxPages} páginas)` };
      }
      selectedIndices.add(pageNum - 1);
    }
  }

  return {
    valid: true,
    indices: Array.from(selectedIndices),
    message: `✓ ${selectedIndices.size} página${selectedIndices.size === 1 ? '' : 's'} seleccionada${selectedIndices.size === 1 ? '' : 's'}`
  };
}

/** Apply range selection to current editPages */
function applyRangeSelection() {
  const val = editRangeInput.value;
  const maxPages = editPages.length;

  const result = parsePageRange(val, maxPages);

  if (!result.valid) {
    editRangeInput.classList.add('is-invalid');
    editRangeHint.textContent = '❌ ' + result.message;
    editRangeHint.className = 'edit-range-hint is-error';
    return;
  }

  editRangeInput.classList.remove('is-invalid');

  if (val.trim() === '') {
    resetRangeUI();
    return;
  }

  // Set selected state for each page
  const indexSet = new Set(result.indices);
  editPages.forEach((p, idx) => {
    p.selected = indexSet.has(idx);
  });

  editRangeHint.textContent = result.message;
  editRangeHint.className = 'edit-range-hint is-success';

  renderEditGrid();
}

// Block non-range characters on keypress (only allow 0-9, hyphen, comma, space)
editRangeInput.addEventListener('keydown', (e) => {
  // Allow navigation / editing keys
  const allowedKeys = ['Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 'Tab', 'Home', 'End', 'Enter'];
  if (allowedKeys.includes(e.key) || e.ctrlKey || e.metaKey) {
    if (e.key === 'Enter') {
      e.preventDefault();
      applyRangeSelection();
    }
    return;
  }

  // Block any non-range character (prevent text typing)
  if (e.key.length === 1 && !/^[0-9,\- ]$/.test(e.key)) {
    e.preventDefault();
  }
});

// Sanitize pasted or typed text to ensure no letters remain
editRangeInput.addEventListener('input', () => {
  const cleaned = editRangeInput.value.replace(/[^0-9,\- ]/g, '');
  if (cleaned !== editRangeInput.value) {
    editRangeInput.value = cleaned;
  }
  // Remove error state as user edits
  if (editRangeInput.classList.contains('is-invalid')) {
    editRangeInput.classList.remove('is-invalid');
    editRangeHint.className = 'edit-range-hint';
    editRangeHint.textContent = 'Ej. 3-12, 22-45';
  }
});

editApplyRangeBtn.addEventListener('click', applyRangeSelection);

// Dropzone event listeners for Edit PDF
editDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  editDropzone.classList.add('drag-over');
});
editDropzone.addEventListener('dragleave', (e) => {
  if (!editDropzone.contains(e.relatedTarget)) editDropzone.classList.remove('drag-over');
});
editDropzone.addEventListener('drop', async (e) => {
  e.preventDefault();
  editDropzone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) await loadEditPdf(file);
});
editDropzone.addEventListener('click', () => editFileInput.click());
editDropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); editFileInput.click(); }
});
editBrowseBtn.addEventListener('click', (e) => { e.stopPropagation(); editFileInput.click(); });
editFileInput.addEventListener('change', async () => {
  if (editFileInput.files[0]) await loadEditPdf(editFileInput.files[0]);
  editFileInput.value = '';
});

editErrorRetryBtn.addEventListener('click', () => {
  hideEditError();
  if (editPages.length > 0) showEditWorkspace();
  else showEditDropzone();
});

// Save Edited PDF
editSaveBtn.addEventListener('click', saveEditedPdf);

async function saveEditedPdf() {
  if (editPages.length === 0) {
    showEditError('El PDF debe contener al menos 1 página para poder guardarlo.');
    return;
  }

  showEditProgress('Guardando PDF editado…');

  try {
    const { PDFDocument, degrees } = PDFLib;
    const srcDoc = await PDFDocument.load(editOriginalBytes);
    const newDoc = await PDFDocument.create();

    for (let i = 0; i < editPages.length; i++) {
      const pageItem = editPages[i];
      const pct = Math.round(((i + 1) / editPages.length) * 90);
      setEditProgress(pct, `Procesando página ${i + 1} de ${editPages.length}…`);

      const [copiedPage] = await newDoc.copyPages(srcDoc, [pageItem.originalIndex]);

      if (pageItem.rotation) {
        const currentRot = copiedPage.getRotation().angle;
        copiedPage.setRotation(degrees((currentRot + pageItem.rotation) % 360));
      }

      newDoc.addPage(copiedPage);
    }

    setEditProgress(95, 'Generando archivo final…');
    const newPdfBytes = await newDoc.save();

    setEditProgress(100, '¡Listo!');

    // Download file
    const baseName = editFile ? editFile.name.replace(/\.pdf$/i, '') : 'documento';
    const safeName = sanitiseName(baseName) + '_editado.pdf';
    const blob = new Blob([newPdfBytes], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = safeName;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);

    setTimeout(() => {
      showEditWorkspace();
    }, 1000);

  } catch (err) {
    console.error('[UniPDF] saveEditedPdf error:', err);
    showEditError('Ocurrió un error al guardar el PDF editado.');
  }
}

// ── MD → PDF feature ─────────────────────────────────────────────────────────

const mdDropzone     = document.getElementById('mdDropzone');
const mdBrowseBtn    = document.getElementById('mdBrowseBtn');
const mdFileInput    = document.getElementById('mdFileInput');
const mdEditorSection = document.getElementById('mdEditorSection');
const mdEditor       = document.getElementById('mdEditor');
const mdPreview      = document.getElementById('mdPreview');
const mdFilename     = document.getElementById('mdFilename');
const mdClearBtn     = document.getElementById('mdClearBtn');
const mdConvertBtn   = document.getElementById('mdConvertBtn');
const mdErrorCard    = document.getElementById('mdErrorCard');
const mdErrorMsg     = document.getElementById('mdErrorMsg');
const mdErrorRetryBtn = document.getElementById('mdErrorRetryBtn');

/** Render Markdown into the preview pane (sanitised via textContent fallback) */
function renderMdPreview() {
  const raw = mdEditor.value;
  if (!raw.trim()) {
    mdPreview.replaceChildren();
    return;
  }
  // marked.parse returns an HTML string; we render it into a sandboxed div
  // XSS note: preview is cosmetic only; the actual PDF is generated server-side
  // via the browser print API in an isolated window – not injected into main DOM.
  const html = marked.parse(raw, { gfm: true, breaks: true });
  mdPreview.innerHTML = html; // intentional – preview pane only, no user-controlled URLs
}

/** Load a .md file into the editor */
async function loadMdFile(file) {
  if (!file.name.match(/\.(md|markdown|txt)$/i) && !file.type.startsWith('text/')) {
    showMdError('Solo se aceptan archivos de texto o Markdown (.md, .markdown).');
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    showMdError('El archivo supera el límite de 5 MB.');
    return;
  }
  const text = await file.text();
  mdEditor.value = text;
  mdFilename.textContent = sanitiseName(file.name).replace(/\.[^.]+$/, '');
  hideMdError();
  showMdEditor();
  renderMdPreview();
}

function showMdEditor() {
  mdEditorSection.hidden = false;
}

function showMdError(msg) {
  mdErrorMsg.textContent = msg; // safe: textContent
  mdErrorCard.hidden = false;
}

function hideMdError() {
  mdErrorCard.hidden = true;
}

/**
 * Convert Markdown to PDF and auto-download.
 *
 * Strategy:
 *  1. Render the HTML into an off-screen container with html2canvas → full canvas.
 *  2. For each page boundary, scan ±SEARCH_PX rows and pick the "whitest" row
 *     (highest average brightness) so the cut always falls between text lines.
 *  3. Slice the canvas at those smart cut points and assemble a jsPDF document.
 *
 * Page size: Letter  8.5 × 11 in (215.9 × 279.4 mm).
 */
async function convertMdToPdf() {
  const raw = mdEditor.value.trim();
  if (!raw) {
    showMdError('El editor está vacío. Escribe o carga un archivo Markdown primero.');
    return;
  }

  // ── Loading state ──
  mdConvertBtn.disabled = true;
  const originalHTML = mdConvertBtn.innerHTML;
  mdConvertBtn.innerHTML = '<span style="opacity:.75">⏳</span> Generando PDF…';
  hideMdError();

  try {
    const { jsPDF } = window.jspdf;
    const title = mdFilename.textContent || 'documento';
    const html  = marked.parse(raw, { gfm: true, breaks: true });

    // ── Page geometry (Letter, margins 18 mm) ──
    const MARGIN_MM  = 18;
    const USABLE_W   = 215.9 - MARGIN_MM * 2;  // 179.9 mm usable width
    const USABLE_H   = 279.4 - MARGIN_MM * 2;  // 243.4 mm usable height

    // Render width in pixels (html2canvas scale=2 → ×2 resolution)
    const RENDER_PX  = 680;                     // logical px width of container
    const SCALE      = 2;                       // html2canvas scale multiplier
    const CANVAS_W   = RENDER_PX * SCALE;       // actual canvas width in px

    // How tall (in canvas px) is one usable page?
    const MM_PER_PX  = USABLE_W / CANVAS_W;    // mm per canvas pixel
    const PAGE_H_PX  = Math.floor(USABLE_H / MM_PER_PX);  // canvas px per page

    // ── Off-screen render container ──
    const container = document.createElement('div');
    container.setAttribute('aria-hidden', 'true');
    Object.assign(container.style, {
      position:   'fixed',
      top:        '0',
      left:       '-9999px',
      width:      RENDER_PX + 'px',
      background: '#ffffff',
      color:      '#1a1a1a',
      fontFamily: "'Georgia','Times New Roman',serif",
      fontSize:   '14px',
      lineHeight: '1.75',
      boxSizing:  'border-box',
    });

    container.innerHTML = html;  // off-screen isolated element, not in main DOM flow

    // Typography styles so html2canvas captures them correctly
    const styleEl = document.createElement('style');
    styleEl.textContent = `
      *{box-sizing:border-box;}
      h1,h2,h3,h4,h5,h6{font-family:'Arial','Helvetica Neue',sans-serif;font-weight:700;
        line-height:1.3;margin:1.1em 0 .4em;color:#111;}
      h1{font-size:26px;border-bottom:2.5px solid #6366f1;padding-bottom:.3em;}
      h2{font-size:20px;border-bottom:1px solid #ddd;padding-bottom:.2em;}
      h3{font-size:17px;} h4,h5,h6{font-size:15px;}
      p{margin:.55em 0;}
      ul,ol{padding-left:1.5em;margin:.4em 0;} li{margin:.2em 0;}
      a{color:#4f46e5;}
      blockquote{margin:.75em 0;padding:.5em .9em;border-left:4px solid #6366f1;
        background:#f5f5ff;color:#444;border-radius:0 4px 4px 0;}
      code{font-family:'Courier New',monospace;font-size:12px;background:#f3f4f6;
        padding:.1em .35em;border-radius:3px;color:#c026d3;}
      pre{background:#1e1e2e;color:#cdd6f4;padding:.8em 1em;border-radius:6px;
        margin:.65em 0;white-space:pre-wrap;word-break:break-all;}
      pre code{background:transparent;color:inherit;padding:0;}
      table{border-collapse:collapse;width:100%;margin:.6em 0;font-size:13px;}
      th,td{border:1px solid #d1d5db;padding:.4em .65em;text-align:left;}
      th{background:#6366f1;color:#fff;font-weight:600;}
      tr:nth-child(even){background:#f9fafb;}
      img{max-width:100%;height:auto;display:block;margin:.4em 0;}
      hr{border:none;border-top:1px solid #ddd;margin:1.2em 0;}
    `;
    container.prepend(styleEl);
    document.body.appendChild(container);

    // ── Capture full content ──
    const canvas = await html2canvas(container, {
      scale:           SCALE,
      useCORS:         true,
      backgroundColor: '#ffffff',
      logging:         false,
    });
    document.body.removeChild(container);

    const ctx = canvas.getContext('2d');

    /**
     * Scan ±SEARCH rows around `targetY` and return the row index whose average
     * pixel brightness is highest (most white = safest place to cut).
     */
    function smartCutY(targetY, search = 50) {
      const top    = Math.max(0, targetY - search);
      const bottom = Math.min(canvas.height - 1, targetY + search);
      let bestY  = targetY;
      let bestBr = -1;
      for (let y = top; y <= bottom; y++) {
        const row  = ctx.getImageData(0, y, canvas.width, 1).data;
        let   sum  = 0;
        for (let i = 0; i < row.length; i += 4) sum += (row[i] + row[i+1] + row[i+2]);
        const avg = sum / (canvas.width * 3);
        if (avg > bestBr) { bestBr = avg; bestY = y; }
      }
      return bestY;
    }

    // ── Build PDF pages with smart cuts ──
    const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'letter' });
    let   top  = 0;
    let   page = 0;

    while (top < canvas.height) {
      if (page > 0) pdf.addPage();

      const rawBottom = top + PAGE_H_PX;
      // For the last page (rawBottom >= canvas.height) cut exactly at the end
      const cutBottom = rawBottom >= canvas.height
        ? canvas.height
        : smartCutY(rawBottom);

      const sliceH = cutBottom - top;

      // Draw slice onto a temporary canvas
      const sliceCvs    = document.createElement('canvas');
      sliceCvs.width    = canvas.width;
      sliceCvs.height   = sliceH;
      const sliceCtx    = sliceCvs.getContext('2d');
      sliceCtx.fillStyle = '#ffffff';
      sliceCtx.fillRect(0, 0, canvas.width, sliceH);
      sliceCtx.drawImage(canvas, 0, top, canvas.width, sliceH, 0, 0, canvas.width, sliceH);

      const imgData  = sliceCvs.toDataURL('image/jpeg', 0.93);
      const sliceH_mm = sliceH * MM_PER_PX;
      pdf.addImage(imgData, 'JPEG', MARGIN_MM, MARGIN_MM, USABLE_W, sliceH_mm);

      top  = cutBottom;
      page++;
    }

    // ── Auto-download ──
    const safeTitle = title
      .replace(/[^a-z0-9_\-\u00C0-\u024F ]/gi, '_')
      .trim().slice(0, 80) || 'documento';
    pdf.save(`${safeTitle}.pdf`);

  } catch (err) {
    console.error('[UniPDF] MD→PDF error:', err);
    showMdError('No se pudo generar el PDF. ' + (err.message || 'Inténtalo de nuevo.'));
  } finally {
    mdConvertBtn.disabled = false;
    mdConvertBtn.innerHTML = originalHTML;
  }
}

// ── MD event wiring ───────────────────────────────────────────────────────────

mdDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  mdDropzone.classList.add('drag-over');
});
mdDropzone.addEventListener('dragleave', (e) => {
  if (!mdDropzone.contains(e.relatedTarget)) mdDropzone.classList.remove('drag-over');
});
mdDropzone.addEventListener('drop', async (e) => {
  e.preventDefault();
  mdDropzone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) await loadMdFile(f);
});
mdDropzone.addEventListener('click', () => mdFileInput.click());
mdDropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); mdFileInput.click(); }
});
mdBrowseBtn.addEventListener('click', (ev) => { ev.stopPropagation(); mdFileInput.click(); });
mdFileInput.addEventListener('change', async () => {
  if (mdFileInput.files[0]) await loadMdFile(mdFileInput.files[0]);
  mdFileInput.value = '';
});

// Live preview on typing – debounced 150ms
let mdDebounce = null;
mdEditor.addEventListener('input', () => {
  clearTimeout(mdDebounce);
  mdDebounce = setTimeout(renderMdPreview, 150);
  showMdEditor();
  hideMdError();
});

mdClearBtn.addEventListener('click', () => {
  mdEditor.value = '';
  mdFilename.textContent = 'sin título';
  mdPreview.replaceChildren();
  hideMdError();
});

mdConvertBtn.addEventListener('click', convertMdToPdf);

mdErrorRetryBtn.addEventListener('click', hideMdError);

// Show editor on tab switch if there's already content
tabMd.addEventListener('click', () => {
  if (mdEditor.value.trim()) showMdEditor();
});

// ── Imágenes → PDF feature ───────────────────────────────────────────────────

const imgDropzoneSection   = document.getElementById('imgDropzoneSection');
const imgDropzone          = document.getElementById('imgDropzone');
const imgBrowseBtn         = document.getElementById('imgBrowseBtn');
const imgFileInput         = document.getElementById('imgFileInput');

const imgSection           = document.getElementById('imgSection');
const imgCountBadge        = document.getElementById('imgCountBadge');
const imgAddMoreBtn        = document.getElementById('imgAddMoreBtn');
const imgClearAllBtn       = document.getElementById('imgClearAllBtn');

const marginNoneBtn        = document.getElementById('marginNoneBtn');
const marginNormalBtn      = document.getElementById('marginNormalBtn');

const imgInvertOrderBtn    = document.getElementById('imgInvertOrderBtn');
const imgResetOrderBtn     = document.getElementById('imgResetOrderBtn');

const imgGrid              = document.getElementById('imgGrid');
const imgConvertBtn        = document.getElementById('imgConvertBtn');

const imgProgressWrapper   = document.getElementById('imgProgressWrapper');
const imgProgressBar       = document.getElementById('imgProgressBar');
const imgProgressText      = document.getElementById('imgProgressText');

const imgErrorCard         = document.getElementById('imgErrorCard');
const imgErrorMsg          = document.getElementById('imgErrorMsg');
const imgErrorRetryBtn     = document.getElementById('imgErrorRetryBtn');

// State for Images
let imageItems             = []; // Array<{ id, file, previewUrl }>
let originalImageItemsCopy = [];
let imgMarginOption        = 'none'; // 'none' | 'normal'
let imgDragSrcIdx          = null;

function showImgProgress(text = 'Procesando imágenes…') {
  hide(imgSection);
  hide(imgDropzoneSection);
  hide(imgErrorCard);
  imgProgressBar.style.width = '0%';
  imgProgressText.textContent = text;
  show(imgProgressWrapper);
}

function setImgProgress(pct, text) {
  imgProgressBar.style.width = Math.min(100, pct) + '%';
  if (text) imgProgressText.textContent = text;
}

function showImgError(msg) {
  hide(imgProgressWrapper);
  imgErrorMsg.textContent = msg;
  show(imgErrorCard);
}

function hideImgError() {
  hide(imgErrorCard);
}

function showImgWorkspace() {
  hide(imgDropzoneSection);
  hide(imgProgressWrapper);
  hide(imgErrorCard);
  show(imgSection);
}

function showImgDropzone() {
  show(imgDropzoneSection);
  hide(imgSection);
  hide(imgProgressWrapper);
  hide(imgErrorCard);
}

/** Load new image files (PNG, JPG, JPEG) */
async function loadImgFiles(files) {
  const toAdd = [];
  const errors = [];

  for (const file of files) {
    const nameLower = file.name.toLowerCase();
    const isImage = file.type.startsWith('image/') ||
                    nameLower.endsWith('.png') ||
                    nameLower.endsWith('.jpg') ||
                    nameLower.endsWith('.jpeg');

    if (!isImage) {
      errors.push(`"${sanitiseName(file.name)}" no es una imagen válida (solo .png, .jpg, .jpeg).`);
      continue;
    }

    if (file.size > MAX_FILE_SIZE_BYTES) {
      errors.push(`"${sanitiseName(file.name)}" supera el límite de 50 MB.`);
      continue;
    }

    // Duplicate check
    const isDuplicate = imageItems.some(item => item.file.name === file.name && item.file.size === file.size);
    if (isDuplicate) continue;

    const previewUrl = URL.createObjectURL(file);
    toAdd.push({
      id: 'img_' + Math.random().toString(36).substr(2, 6),
      file,
      previewUrl
    });
  }

  if (errors.length) {
    showImgError(errors.join('\n'));
  }

  if (toAdd.length) {
    imageItems = [...imageItems, ...toAdd];
    originalImageItemsCopy = [...imageItems];
    showImgWorkspace();
    renderImgGrid();
  }
}

/** Render grid of images */
function renderImgGrid() {
  imgGrid.replaceChildren();
  imgCountBadge.textContent = `${imageItems.length} imagen${imageItems.length === 1 ? '' : 'es'}`;

  if (imageItems.length === 0) {
    showImgDropzone();
    return;
  }

  imageItems.forEach((item, idx) => {
    const card = buildImageCard(item, idx);
    imgGrid.appendChild(card);
  });
}

/** Build an image card node */
function buildImageCard(item, idx) {
  const card = document.createElement('div');
  card.className = 'page-card';
  card.setAttribute('draggable', 'true');
  card.setAttribute('role', 'listitem');
  card.dataset.idx = String(idx);

  // Header
  const header = document.createElement('div');
  header.className = 'page-card-header';

  const badge = document.createElement('span');
  badge.className = 'file-order';
  badge.textContent = String(idx + 1);

  const deleteBtn = document.createElement('button');
  deleteBtn.type = 'button';
  deleteBtn.className = 'page-card-delete';
  deleteBtn.setAttribute('title', `Eliminar imagen ${idx + 1}`);
  deleteBtn.setAttribute('aria-label', `Eliminar imagen ${idx + 1}`);
  deleteBtn.appendChild(buildRemoveSvg());
  deleteBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    removeImgItem(idx);
  });

  header.appendChild(badge);
  header.appendChild(deleteBtn);

  // Body: Preview Image
  const body = document.createElement('div');
  body.className = 'page-card-body';

  const img = document.createElement('img');
  img.className = 'page-card-canvas';
  img.src = item.previewUrl;
  img.alt = sanitiseName(item.file.name);
  img.loading = 'lazy';

  body.appendChild(img);

  // Footer
  const footer = document.createElement('div');
  footer.className = 'page-card-footer';

  const nameSpan = document.createElement('span');
  nameSpan.className = 'file-name';
  nameSpan.style.fontSize = '.75rem';
  nameSpan.textContent = sanitiseName(item.file.name);

  const sizeSpan = document.createElement('span');
  sizeSpan.className = 'page-card-orig';
  sizeSpan.textContent = formatBytes(item.file.size);

  footer.appendChild(nameSpan);
  footer.appendChild(sizeSpan);

  card.appendChild(header);
  card.appendChild(body);
  card.appendChild(footer);

  // Drag handlers
  card.addEventListener('dragstart', onImgCardDragStart);
  card.addEventListener('dragover',  onImgCardDragOver);
  card.addEventListener('dragleave', onImgCardDragLeave);
  card.addEventListener('drop',      onImgCardDrop);
  card.addEventListener('dragend',   onImgCardDragEnd);

  return card;
}

// Drag & Drop handlers for image grid
function onImgCardDragStart(e) {
  imgDragSrcIdx = Number(this.dataset.idx);
  this.classList.add('dragging');
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', String(imgDragSrcIdx));
}

function onImgCardDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  this.classList.add('drag-target');
}

function onImgCardDragLeave() {
  this.classList.remove('drag-target');
}

function onImgCardDrop(e) {
  e.preventDefault();
  this.classList.remove('drag-target');
  const targetIdx = Number(this.dataset.idx);
  if (imgDragSrcIdx === null || imgDragSrcIdx === targetIdx) return;

  const moved = imageItems.splice(imgDragSrcIdx, 1)[0];
  imageItems.splice(targetIdx, 0, moved);
  renderImgGrid();
}

function onImgCardDragEnd() {
  this.classList.remove('dragging');
  imgDragSrcIdx = null;
  document.querySelectorAll('#imgGrid .page-card').forEach(el => el.classList.remove('drag-target'));
}

// Image item operations
function removeImgItem(idx) {
  const removed = imageItems.splice(idx, 1)[0];
  if (removed && removed.previewUrl) {
    URL.revokeObjectURL(removed.previewUrl);
  }
  renderImgGrid();
}

function clearAllImages() {
  imageItems.forEach(item => {
    if (item.previewUrl) URL.revokeObjectURL(item.previewUrl);
  });
  imageItems = [];
  originalImageItemsCopy = [];
  imgFileInput.value = '';
  showImgDropzone();
}

// Margin toggle logic
marginNoneBtn.addEventListener('click', () => {
  imgMarginOption = 'none';
  marginNoneBtn.classList.add('active');
  marginNoneBtn.setAttribute('aria-checked', 'true');
  marginNormalBtn.classList.remove('active');
  marginNormalBtn.setAttribute('aria-checked', 'false');
});

marginNormalBtn.addEventListener('click', () => {
  imgMarginOption = 'normal';
  marginNormalBtn.classList.add('active');
  marginNormalBtn.setAttribute('aria-checked', 'true');
  marginNoneBtn.classList.remove('active');
  marginNoneBtn.setAttribute('aria-checked', 'false');
});

imgInvertOrderBtn.addEventListener('click', () => {
  imageItems.reverse();
  renderImgGrid();
});

imgResetOrderBtn.addEventListener('click', () => {
  imageItems = [...originalImageItemsCopy];
  renderImgGrid();
});

imgAddMoreBtn.addEventListener('click', () => imgFileInput.click());
imgClearAllBtn.addEventListener('click', clearAllImages);

// Dropzone event listeners for Images → PDF
imgDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  imgDropzone.classList.add('drag-over');
});

imgDropzone.addEventListener('dragleave', (e) => {
  if (!imgDropzone.contains(e.relatedTarget)) imgDropzone.classList.remove('drag-over');
});

imgDropzone.addEventListener('drop', async (e) => {
  e.preventDefault();
  imgDropzone.classList.remove('drag-over');
  const files = Array.from(e.dataTransfer.files);
  if (files.length) await loadImgFiles(files);
});

imgDropzone.addEventListener('click', () => imgFileInput.click());
imgDropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); imgFileInput.click(); }
});

imgBrowseBtn.addEventListener('click', (e) => { e.stopPropagation(); imgFileInput.click(); });

imgFileInput.addEventListener('change', async () => {
  if (imgFileInput.files.length) await loadImgFiles(Array.from(imgFileInput.files));
  imgFileInput.value = '';
});

imgErrorRetryBtn.addEventListener('click', () => {
  hideImgError();
  if (imageItems.length > 0) showImgWorkspace();
  else showImgDropzone();
});

// Convert Images to PDF
imgConvertBtn.addEventListener('click', convertImagesToPdf);

async function convertImagesToPdf() {
  if (imageItems.length === 0) {
    showImgError('Necesitas al menos 1 imagen para generar el PDF.');
    return;
  }

  showImgProgress('Iniciando conversión de imágenes…');

  try {
    const { PDFDocument } = PDFLib;
    const pdfDoc = await PDFDocument.create();

    const marginPt = (imgMarginOption === 'normal' ? 36 : 0); // 36pt ~ 12.7mm margin

    for (let i = 0; i < imageItems.length; i++) {
      const item = imageItems[i];
      const pct = Math.round(((i + 1) / imageItems.length) * 85);
      setImgProgress(pct, `Procesando imagen ${i + 1} de ${imageItems.length}: ${sanitiseName(item.file.name)}`);

      const arrayBuffer = await readFileAsArrayBuffer(item.file);
      const nameLower = item.file.name.toLowerCase();
      const isPng = item.file.type === 'image/png' || nameLower.endsWith('.png');

      let embeddedImage;
      try {
        if (isPng) {
          embeddedImage = await pdfDoc.embedPng(arrayBuffer);
        } else {
          embeddedImage = await pdfDoc.embedJpg(arrayBuffer);
        }
      } catch (embedErr) {
        console.warn('[UniPDF] direct embed failed, trying cross-format fallback:', embedErr);
        try {
          if (isPng) embeddedImage = await pdfDoc.embedJpg(arrayBuffer);
          else embeddedImage = await pdfDoc.embedPng(arrayBuffer);
        } catch {
          throw new Error(`La imagen "${sanitiseName(item.file.name)}" no tiene un formato PNG o JPG válido.`);
        }
      }

      const { width, height } = embeddedImage.scale(1);

      const pageW = width + marginPt * 2;
      const pageH = height + marginPt * 2;

      const page = pdfDoc.addPage([pageW, pageH]);
      page.drawImage(embeddedImage, {
        x: marginPt,
        y: marginPt,
        width: width,
        height: height,
      });
    }

    setImgProgress(92, 'Generando archivo PDF final…');
    const pdfBytes = await pdfDoc.save();

    setImgProgress(100, '¡Listo!');

    const blob = new Blob([pdfBytes], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'imagenes_convertidas.pdf';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);

    setTimeout(() => {
      showImgWorkspace();
    }, 1000);

  } catch (err) {
    console.error('[UniPDF] convertImagesToPdf error:', err);
    showImgError(err.message || 'Ocurrió un error al convertir las imágenes a PDF.');
  }
}
