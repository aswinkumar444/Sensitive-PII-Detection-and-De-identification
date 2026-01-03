// Global variables
let selectedFile = null;
let piiTypes = [];
let piiLabels = {};
let presets = [];
let currentResults = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
});

async function initializeApp() {
    try {
        // Load PII types and presets
        await loadPiiTypes();
        await loadPresets();
        
        // Initialize UI components
        initializeCustomPatterns();
        initializeMaskingTable();
        
        showToast('Application initialized successfully', 'success');
    } catch (error) {
        console.error('Failed to initialize app:', error);
        showToast('Failed to initialize application', 'error');
    }
}

function setupEventListeners() {
    // File input handling
    const fileInput = document.getElementById('fileInput');
    const uploadArea = document.getElementById('uploadArea');
    
    fileInput.addEventListener('change', handleFileSelect);
    
    // Drag and drop
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleFileDrop);
    
    // Pattern mode toggle
    const patternModeInputs = document.querySelectorAll('input[name="patternMode"]');
    patternModeInputs.forEach(input => {
        input.addEventListener('change', togglePatternMode);
    });
    
    // Tab switching
    window.switchTab = switchTab;
    window.switchResultTab = switchResultTab;
    window.clearFile = clearFile;
    window.runDetection = runDetection;
    window.downloadDeidentified = downloadDeidentified;
    window.downloadSummary = downloadSummary;
}

async function loadPiiTypes() {
    try {
        const response = await fetch('/api/pii-types');
        const data = await response.json();
        piiTypes = data.types;
        piiLabels = data.labels;
    } catch (error) {
        console.error('Failed to load PII types:', error);
        throw error;
    }
}

async function loadPresets() {
    try {
        const response = await fetch('/api/presets');
        presets = await response.json();
        
        const presetSelect = document.getElementById('presetSelect');
        presetSelect.innerHTML = '';
        presets.forEach(preset => {
            const option = document.createElement('option');
            option.value = preset;
            option.textContent = preset;
            presetSelect.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load presets:', error);
        throw error;
    }
}

function initializeCustomPatterns() {
    const customPatternsContainer = document.getElementById('customPatterns');
    customPatternsContainer.innerHTML = '';
    
    piiTypes.forEach(type => {
        const row = document.createElement('div');
        row.className = 'pattern-row';
        
        const label = document.createElement('label');
        label.textContent = piiLabels[type] || type.charAt(0).toUpperCase() + type.slice(1);
        
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'form-control';
        input.id = `pattern-${type}`;
        input.placeholder = `Enter regex pattern for ${piiLabels[type] || type}`;
        
        row.appendChild(label);
        row.appendChild(input);
        customPatternsContainer.appendChild(row);
    });
}

function initializeMaskingTable() {
    const maskingRowsContainer = document.getElementById('maskingRows');
    maskingRowsContainer.innerHTML = '';
    
    const strategies = ['partial', 'full', 'hash', 'encrypt', 'redact'];
    const strategyLabels = {
        'partial': 'De-identification (Default)',
        'full': 'Full Mask',
        'hash': 'Hash (SHA256)',
        'encrypt': 'Encryption',
        'redact': 'Redact'
    };
    
    piiTypes.forEach(type => {
        const row = document.createElement('div');
        row.className = 'masking-row';
        
        // PII Type Label
        const typeLabel = document.createElement('label');
        typeLabel.textContent = piiLabels[type] || type.charAt(0).toUpperCase() + type.slice(1);
        
        // Enable checkbox
        const enableCheckbox = document.createElement('input');
        enableCheckbox.type = 'checkbox';
        enableCheckbox.id = `enable-${type}`;
        enableCheckbox.checked = true;
        
        // Strategy select
        const strategySelect = document.createElement('select');
        strategySelect.id = `strategy-${type}`;
        strategies.forEach(strategy => {
            const option = document.createElement('option');
            option.value = strategy;
            option.textContent = strategyLabels[strategy];
            strategySelect.appendChild(option);
        });
        
        // Mask character input
        const maskCharInput = document.createElement('input');
        maskCharInput.type = 'text';
        maskCharInput.id = `char-${type}`;
        maskCharInput.value = '*';
        maskCharInput.maxLength = 1;
        maskCharInput.style.width = '60px';
        maskCharInput.style.textAlign = 'center';
        
        // Expected count input
        const expectedCountInput = document.createElement('input');
        expectedCountInput.type = 'number';
        expectedCountInput.id = `expected-${type}`;
        expectedCountInput.min = '0';
        expectedCountInput.placeholder = 'Optional';
        expectedCountInput.style.width = '100px';
        
        row.appendChild(typeLabel);
        row.appendChild(enableCheckbox);
        row.appendChild(strategySelect);
        row.appendChild(maskCharInput);
        row.appendChild(expectedCountInput);
        
        maskingRowsContainer.appendChild(row);
    });
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        setSelectedFile(file);
    }
}

function handleDragOver(event) {
    event.preventDefault();
    event.currentTarget.classList.add('dragover');
}

function handleDragLeave(event) {
    event.currentTarget.classList.remove('dragover');
}

function handleFileDrop(event) {
    event.preventDefault();
    event.currentTarget.classList.remove('dragover');
    
    const files = event.dataTransfer.files;
    if (files.length > 0) {
        setSelectedFile(files[0]);
    }
}

function setSelectedFile(file) {
    const allowedTypes = ['text/csv', 'text/plain', 'application/pdf'];
    const allowedExtensions = ['.csv', '.txt', '.pdf'];
    
    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    
    if (!allowedTypes.includes(file.type) && !allowedExtensions.includes(fileExtension)) {
        showToast('Please select a CSV, TXT, or PDF file', 'error');
        return;
    }
    
    selectedFile = file;
    
    // Update UI
    document.getElementById('uploadArea').style.display = 'none';
    document.getElementById('fileInfo').style.display = 'block';
    document.getElementById('fileName').textContent = file.name;
    
    // Clear previous results
    document.getElementById('resultsSection').style.display = 'none';
    currentResults = null;
}

function clearFile() {
    selectedFile = null;
    document.getElementById('fileInput').value = '';
    document.getElementById('uploadArea').style.display = 'block';
    document.getElementById('fileInfo').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'none';
    currentResults = null;
}

function togglePatternMode() {
    const usePreset = document.querySelector('input[name="patternMode"]:checked').value === 'preset';
    
    document.getElementById('presetSection').style.display = usePreset ? 'block' : 'none';
    document.getElementById('customSection').style.display = usePreset ? 'none' : 'block';
}

function switchTab(tabName) {
    // Remove active class from all tabs
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    // Add active class to selected tab
    event.target.classList.add('active');
    document.getElementById(tabName + 'Tab').classList.add('active');
}

function switchResultTab(tabName) {
    // Remove active class from all result tabs
    document.querySelectorAll('.result-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.result-tab-content').forEach(content => content.classList.remove('active'));
    
    // Add active class to selected tab
    event.target.classList.add('active');
    document.getElementById(tabName + 'Tab').classList.add('active');
}

async function runDetection() {
    if (!selectedFile) {
        showToast('Please select a file first', 'warning');
        return;
    }
    
    // Show loading
    document.getElementById('loadingOverlay').style.display = 'flex';
    document.getElementById('runDetection').disabled = true;
    
    try {
        // Prepare configuration
        const config = prepareConfiguration();
        
        // Create form data
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('config', JSON.stringify(config));
        
        // Send request
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            currentResults = result;
            displayResults(result);
            showToast('Detection completed successfully', 'success');
        } else {
            showToast('Error: ' + result.error, 'error');
        }
    } catch (error) {
        console.error('Detection failed:', error);
        showToast('Detection failed: ' + error.message, 'error');
    } finally {
        // Hide loading
        document.getElementById('loadingOverlay').style.display = 'none';
        document.getElementById('runDetection').disabled = false;
    }
}

function prepareConfiguration() {
    const usePreset = document.querySelector('input[name="patternMode"]:checked').value === 'preset';
    
    const config = {
        use_preset: usePreset,
        preset: usePreset ? document.getElementById('presetSelect').value : null,
        custom_patterns: {},
        mask_configs: {},
        expected_counts: {}
    };
    
    // Custom patterns
    if (!usePreset) {
        piiTypes.forEach(type => {
            const input = document.getElementById(`pattern-${type}`);
            if (input && input.value.trim()) {
                config.custom_patterns[type] = input.value.trim();
            }
        });
    }
    
    // Mask configurations
    piiTypes.forEach(type => {
        config.mask_configs[type] = {
            enabled: document.getElementById(`enable-${type}`).checked,
            strategy: document.getElementById(`strategy-${type}`).value,
            char: document.getElementById(`char-${type}`).value || '*'
        };
        
        const expectedInput = document.getElementById(`expected-${type}`);
        if (expectedInput.value) {
            config.expected_counts[type] = parseInt(expectedInput.value);
        }
    });
    
    return config;
}

function displayResults(results) {
    displaySummaryStats(results.summary);
    displayMetricsTable(results.report_metrics);
    displayPreviewTable(results.headers, results.deidentified_rows);
    
    document.getElementById('resultsSection').style.display = 'block';
}

function displaySummaryStats(summary) {
    const statsContainer = document.getElementById('summaryStats');
    statsContainer.innerHTML = '';
    
    // Rows processed
    const rowsCard = createStatCard('Rows Processed', summary.rows_processed);
    statsContainer.appendChild(rowsCard);
    
    // Total matches
    const totalMatches = Object.values(summary.matches).reduce((sum, count) => sum + count, 0);
    const matchesCard = createStatCard('Total PII Found', totalMatches);
    statsContainer.appendChild(matchesCard);
    
    // PII types found
    const typesFound = Object.values(summary.matches).filter(count => count > 0).length;
    const typesCard = createStatCard('PII Types Found', typesFound);
    statsContainer.appendChild(typesCard);
}

function createStatCard(title, value) {
    const card = document.createElement('div');
    card.className = 'stat-card';
    card.innerHTML = `
        <h4>${title}</h4>
        <div class="value">${value}</div>
    `;
    return card;
}

function displayMetricsTable(metrics) {
    const tableContainer = document.getElementById('metricsTable');
    
    const table = document.createElement('table');
    table.className = 'data-table';
    
    // Header
    const thead = document.createElement('thead');
    thead.innerHTML = `
        <tr>
            <th>PII Category</th>
            <th>Found</th>
            <th>Expected</th>
            <th>TP</th>
            <th>FP</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1-Score</th>
            <th>Risk Level</th>
        </tr>
    `;
    table.appendChild(thead);
    
    // Body
    const tbody = document.createElement('tbody');
    Object.entries(metrics).forEach(([type, metric]) => {
        const row = document.createElement('tr');
        const riskClass = `risk-${metric.risk.toLowerCase()}`;
        
        row.innerHTML = `
            <td>${piiLabels[type] || type}</td>
            <td>${metric.found}</td>
            <td>${metric.expected !== null ? metric.expected : 'N/A'}</td>
            <td>${metric.tp}</td>
            <td>${metric.fp}</td>
            <td>${metric.precision.toFixed(2)}</td>
            <td>${metric.recall.toFixed(2)}</td>
            <td>${metric.f1.toFixed(2)}</td>
            <td class="${riskClass}">${metric.risk}</td>
        `;
        tbody.appendChild(row);
    });
    table.appendChild(tbody);
    
    tableContainer.innerHTML = '';
    tableContainer.appendChild(table);
}

function displayPreviewTable(headers, rows) {
    const table = document.getElementById('previewTable');
    table.innerHTML = '';
    
    if (headers.length === 0 || rows.length === 0) {
        table.innerHTML = '<tr><td>No data to preview</td></tr>';
        return;
    }
    
    // Header
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    headers.forEach(header => {
        const th = document.createElement('th');
        th.textContent = header;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);
    
    // Body (show first 100 rows)
    const tbody = document.createElement('tbody');
    const maxRows = Math.min(rows.length, 100);
    
    for (let i = 0; i < maxRows; i++) {
        const row = document.createElement('tr');
        rows[i].forEach(cell => {
            const td = document.createElement('td');
            td.textContent = cell;
            row.appendChild(td);
        });
        tbody.appendChild(row);
    }
    
    if (rows.length > 100) {
        const row = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = headers.length;
        td.textContent = `... and ${rows.length - 100} more rows`;
        td.style.textAlign = 'center';
        td.style.fontStyle = 'italic';
        row.appendChild(td);
        tbody.appendChild(row);
    }
    
    table.appendChild(tbody);
}

function downloadDeidentified() {
    if (!currentResults) {
        showToast('No data to download', 'warning');
        return;
    }
    
    const { headers, deidentified_rows } = currentResults;
    
    // Create CSV content
    let csvContent = '';
    if (headers.length > 0) {
        csvContent += headers.join(',') + '\n';
    }
    
    deidentified_rows.forEach(row => {
        csvContent += row.map(cell => `"${cell}"`).join(',') + '\n';
    });
    
    // Download file
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedFile.name.split('.')[0]}_deidentified.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showToast('De-identified data downloaded', 'success');
}

function downloadSummary() {
    if (!currentResults) {
        showToast('No summary to download', 'warning');
        return;
    }
    
    // Generate summary report text
    let reportText = '--- Detection Summary Report ---\n\n';
    reportText += `Rows Processed: ${currentResults.summary.rows_processed}\n\n`;
    
    reportText += 'PII Detection Results:\n';
    reportText += '-'.repeat(80) + '\n';
    reportText += `${'PII Category'.padEnd(20)} | ${'Found'.padEnd(7)} | ${'Expected'.padEnd(10)} | ${'TP'.padEnd(5)} | ${'FP'.padEnd(5)} | ${'Precision'.padEnd(10)} | ${'Recall'.padEnd(8)} | ${'F1-Score'.padEnd(10)} | Risk Level\n`;
    reportText += '-'.repeat(80) + '\n';
    
    Object.entries(currentResults.report_metrics).forEach(([type, metrics]) => {
        const expectedStr = metrics.expected !== null ? metrics.expected.toString() : 'N/A';
        const line = `${(piiLabels[type] || type).padEnd(20)} | ${metrics.found.toString().padEnd(7)} | ${expectedStr.padEnd(10)} | ${metrics.tp.toString().padEnd(5)} | ${metrics.fp.toString().padEnd(5)} | ${metrics.precision.toFixed(2).padEnd(10)} | ${metrics.recall.toFixed(2).padEnd(8)} | ${metrics.f1.toFixed(2).padEnd(10)} | ${metrics.risk}`;
        reportText += line + '\n';
    });
    
    reportText += '\n' + '='.repeat(40) + '\n\n';
    reportText += '--- Accuracy Formulas ---\n\n';
    reportText += 'Precision = TP / (TP + FP)  (Ability to avoid false positives)\n';
    reportText += 'Recall    = TP / (TP + FN)  (Ability to find all positives)\n';
    reportText += 'F1-Score  = 2 * (Precision * Recall) / (Precision + Recall)\n\n';
    reportText += '--- Risk Matrix ---\n\n';
    reportText += 'Low:      All found items were expected (Precision = 1.0)\n';
    reportText += 'Medium:   High precision (>= 0.8), few false positives.\n';
    reportText += 'High:     Moderate precision (>= 0.5), some false positives.\n';
    reportText += 'Critical: Low precision (< 0.5) or found items when none expected.\n';
    
    // Download file
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'summary_report.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showToast('Summary report downloaded', 'success');
}

function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <i class="fas fa-${getToastIcon(type)}"></i>
            <span>${message}</span>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    }, 5000);
    
    // Click to dismiss
    toast.addEventListener('click', () => {
        if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
        }
    });
}

function getToastIcon(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}
