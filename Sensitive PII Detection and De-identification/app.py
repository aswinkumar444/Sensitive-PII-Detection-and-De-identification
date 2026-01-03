import sys
import csv
import os
import re
from typing import Dict, List, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QMessageBox, QSplitter,
    QGroupBox, QGridLayout, QComboBox, QLineEdit, QCheckBox,
    QTabWidget, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QRadioButton, QStackedWidget
)
from PySide6.QtCore import Qt, QThread, Signal, QObject
from PySide6.QtGui import QFont, QIntValidator, QCloseEvent

from pii_utils import (
    detect_and_deidentify_record, get_preset_patterns,
    get_available_presets, PII_HANDLERS, PATTERN_PRESETS
)

STYLESHEET = """
    QMainWindow, QWidget { background-color: #1E1E1E; font-family: 'Segoe UI'; color: #EAEAEA; }
    QGroupBox { background-color: #2C2C2C; border: 1px solid #3A3A3A; border-radius: 8px; margin-top: 10px; font-size: 11pt; font-weight: bold; color: #EAEAEA; }
    QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 10px; }
    QPushButton { font-size: 10pt; padding: 8px 16px; border-radius: 4px; background-color: #3A3A3A; border: 1px solid #555; color: #EAEAEA; }
    QPushButton:hover { background-color: #505050; }
    QPushButton#Accent { background-color: #50C878; color: white; font-weight: bold; border: none; }
    QPushButton#Accent:hover { background-color: #45a049; }
    QPushButton#Nav { background-color: #4A90E2; color: white; font-weight: bold; border: none; }
    QPushButton#Nav:hover { background-color: #357ABD; }
    QLabel { font-size: 10pt; background-color: transparent; color: #EAEAEA; }
    QLineEdit, QComboBox { font-size: 10pt; padding: 5px; border: 1px solid #555; border-radius: 4px; background-color: #2C2C2C; color: #EAEAEA; }
    QTableWidget { border: 1px solid #3A3A3A; gridline-color: #505050; background-color: #1E1E1E; color: #EAEAEA; }
    QHeaderView::section { background-color: #333; padding: 4px; border: 1px solid #444; font-weight: bold; color: #EAEAEA; }
    QTabWidget::pane { border: 1px solid #3A3A3A; border-top: none; }
    QTabBar::tab { background: #2C2C2C; padding: 10px; border: 1px solid #444; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; color: #EAEAEA; }
    QTabBar::tab:selected { background: #1E1E1E; }
"""

class Worker(QObject):
    finished = Signal(object)
    error = Signal(str)
    def __init__(self, input_path, patterns, mask_configs, expected_counts):
        super().__init__()
        self.input_path, self.patterns, self.mask_configs, self.expected_counts = input_path, patterns, mask_configs, expected_counts
        self._is_interrupted = False

    def run(self):
        try:
            headers, input_rows = [], []
            file_ext = os.path.splitext(self.input_path)[1].lower()
            if file_ext == '.csv': headers, input_rows = self._read_csv()
            elif file_ext == '.txt': headers, input_rows = self._read_txt()
            elif file_ext == '.pdf':
                if fitz is None: raise ImportError("PyMuPDF is not installed. Please run 'pip install PyMuPDF' to process PDF files.")
                headers, input_rows = self._read_pdf()
            
            run_context, deidentified_rows = {}, []
            summary = {"rows_processed": 0, "matches": {key: 0 for key in PII_HANDLERS}}
            for row in input_rows:
                if self._is_interrupted: break
                deid_row, row_counts = detect_and_deidentify_record(row, self.patterns, self.mask_configs, context=run_context)
                deidentified_rows.append(deid_row); summary["rows_processed"] += 1
                for key in summary["matches"]: summary["matches"][key] += row_counts.get(key, 0)
            
            if not self._is_interrupted:
                report_metrics = self._calculate_metrics(summary)
                self.finished.emit((headers, deidentified_rows, summary, report_metrics))
        except Exception as e:
            self.error.emit(f"Failed to process file:\n{e}")

    def stop(self): self._is_interrupted = True

    def _calculate_metrics(self, summary):
        metrics = {}
        for key in PII_HANDLERS.keys():
            found = summary['matches'].get(key, 0)
            expected = self.expected_counts.get(key, None)
            tp = min(found, expected) if expected is not None else found
            fp = max(0, found - expected) if expected is not None else 0
            fn = max(0, expected - found) if expected is not None else 0
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            risk_level = "N/A"
            if expected is not None:
                if tp == 0 and fp > 0: risk_level = "Critical"
                elif tp > 0 and fp == 0: risk_level = "Low"
                elif precision >= 0.8: risk_level = "Medium"
                elif precision >= 0.5: risk_level = "High"
                else: risk_level = "Critical"
            metrics[key] = {"found": found, "expected": expected, "tp": tp, "fp": fp, "precision": precision, "recall": recall, "f1": f1, "risk": risk_level}
        return metrics

    def _read_csv(self):
        with open(self.input_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f); headers = next(reader, []); rows = list(reader)
        return headers, rows

    def _read_txt(self):
        with open(self.input_path, "r", encoding="utf-8") as f: rows = [[line.strip()] for line in f]
        return ["Text"], rows
    
    def _read_pdf(self):
        rows, doc = [], fitz.open(self.input_path)
        for page in doc:
            for line in page.get_text().splitlines():
                if line.strip(): rows.append([line.strip()])
        return ["Extracted Text"], rows

class PiiApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PII Detection & De-Identification Tool"); self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet(STYLESHEET)
        self.input_path: Optional[str] = None; self.input_file_type: str = ""; self.deidentified_rows: List[List[str]] = []; self.headers: List[str] = []; self.summary: Dict = {}; self.report_metrics: Dict = {}
        self.pii_types = list(PII_HANDLERS.keys())
        self.pii_labels = {"aadhaar": "Aadhaar", "pan": "PAN", "credit_card": "Credit Card", "email": "Email", "passport": "Passport", "driving_license": "Driving License", "phone": "Phone", "person": "Person Name"}
        self.mask_config_widgets: Dict[str, Dict] = {}; self.regex_widgets: Dict[str, QLineEdit] = {}; self.expected_count_widgets: Dict[str, QLineEdit] = {}
        self.thread: Optional[QThread] = None; self.worker: Optional[Worker] = None
        self._init_ui()

    def _init_ui(self):
        central_widget = QWidget(); self.setCentralWidget(central_widget); main_layout = QVBoxLayout(central_widget)
        header = QWidget(); header.setStyleSheet("background-color: #4A90E2; color: white; border-radius: 5px;"); header_layout = QVBoxLayout(header)
        title = QLabel("PII Detection & De-Identification Tool"); title.setFont(QFont("Segoe UI", 16, QFont.Bold)); title.setStyleSheet("color: white;")
        subtitle = QLabel("Scan files, configure masking, and generate advanced accuracy reports."); subtitle.setFont(QFont("Segoe UI", 10)); subtitle.setStyleSheet("color: white;")
        header_layout.addWidget(title); header_layout.addWidget(subtitle); main_layout.addWidget(header)
        controls_layout = QHBoxLayout(); select_button = QPushButton("Select Input File"); select_button.clicked.connect(self._select_file)
        self.path_label = QLabel("No file selected."); self.path_label.setStyleSheet("font-style: italic; color: #555;")
        self.run_button = QPushButton("Run Detection"); self.run_button.setObjectName("Accent"); self.run_button.clicked.connect(self._run_detection)
        self.progress_bar = QProgressBar(); self.progress_bar.setVisible(False); self.progress_bar.setMaximum(0)
        controls_layout.addWidget(select_button); controls_layout.addWidget(self.path_label, 1); controls_layout.addWidget(self.run_button); controls_layout.addWidget(self.progress_bar)
        main_layout.addLayout(controls_layout); splitter = QSplitter(Qt.Horizontal); main_layout.addWidget(splitter, 1)
        left_pane = QWidget(); left_layout = QVBoxLayout(left_pane); splitter.addWidget(left_pane)
        self.config_stack = QStackedWidget(); left_layout.addWidget(self.config_stack)
        regex_page = QWidget(); regex_page_layout = QVBoxLayout(regex_page)
        regex_group = QGroupBox("Step 1: Regex Pattern Configuration"); regex_layout = QVBoxLayout(regex_group)
        mode_layout = QHBoxLayout(); self.preset_radio = QRadioButton("Use Preset"); self.custom_radio = QRadioButton("Use Custom")
        self.preset_radio.setChecked(True); self.preset_radio.toggled.connect(self._on_pattern_mode_change); mode_layout.addWidget(self.preset_radio); mode_layout.addWidget(self.custom_radio); mode_layout.addStretch(); regex_layout.addLayout(mode_layout)
        self.preset_combo = QComboBox(); self.preset_combo.addItems(get_available_presets()); regex_layout.addWidget(self.preset_combo)
        self.custom_regex_widgets = QWidget(); custom_layout = QGridLayout(self.custom_regex_widgets)
        for i, key in enumerate(self.pii_types):
            default_pattern = PATTERN_PRESETS["Indian (Default)"].get(key, ""); self.regex_widgets[key] = QLineEdit(default_pattern)
            custom_layout.addWidget(QLabel(self.pii_labels.get(key, key.title())), i, 0); custom_layout.addWidget(self.regex_widgets[key], i, 1)
        self.custom_regex_widgets.setEnabled(False); regex_layout.addWidget(self.custom_regex_widgets); regex_page_layout.addWidget(regex_group)
        next_button = QPushButton("Next: Configure De-Identification →"); next_button.setObjectName("Nav"); next_button.clicked.connect(lambda: self.config_stack.setCurrentIndex(1))
        regex_page_layout.addWidget(next_button, 0, Qt.AlignRight); regex_page_layout.addStretch()
        deid_page = QWidget(); deid_page_layout = QVBoxLayout(deid_page)
        mask_group = QGroupBox("Step 2: De-Identification & Validation"); mask_layout = QGridLayout(mask_group)
        mask_layout.addWidget(QLabel("<b>PII Type</b>"), 0, 0); mask_layout.addWidget(QLabel("<b>Mask?</b>"), 0, 1); mask_layout.addWidget(QLabel("<b>Strategy</b>"), 0, 2); mask_layout.addWidget(QLabel("<b>Char</b>"), 0, 3); mask_layout.addWidget(QLabel("<b>Expected #</b>"), 0, 4)
        masking_strategies = ["Partial Mask (Default)", "Full Mask", "Hash (SHA256)", "Encryption", "Redact"]
        for i, key in enumerate(self.pii_types):
            self.mask_config_widgets[key] = {"enabled": QCheckBox(), "strategy": QComboBox(), "char": QLineEdit("*")}
            self.expected_count_widgets[key] = QLineEdit(); self.expected_count_widgets[key].setValidator(QIntValidator(0, 999999)); self.expected_count_widgets[key].setFixedWidth(80)
            self.mask_config_widgets[key]["enabled"].setChecked(True); self.mask_config_widgets[key]["strategy"].addItems(masking_strategies)
            self.mask_config_widgets[key]["char"].setMaxLength(1); self.mask_config_widgets[key]["char"].setFixedWidth(40)
            mask_layout.addWidget(QLabel(self.pii_labels.get(key, key.title())), i + 1, 0); mask_layout.addWidget(self.mask_config_widgets[key]["enabled"], i + 1, 1); mask_layout.addWidget(self.mask_config_widgets[key]["strategy"], i + 1, 2); mask_layout.addWidget(self.mask_config_widgets[key]["char"], i + 1, 3); mask_layout.addWidget(self.expected_count_widgets[key], i + 1, 4)
        deid_page_layout.addWidget(mask_group)
        back_button = QPushButton("← Back to Regex"); back_button.setObjectName("Nav"); back_button.clicked.connect(lambda: self.config_stack.setCurrentIndex(0))
        deid_page_layout.addWidget(back_button, 0, Qt.AlignLeft); deid_page_layout.addStretch()
        self.config_stack.addWidget(regex_page); self.config_stack.addWidget(deid_page)
        right_pane = QWidget(); right_layout = QVBoxLayout(right_pane); splitter.addWidget(right_pane)
        self.tabs = QTabWidget(); self.summary_text = QTextEdit(); self.summary_text.setReadOnly(True); self.summary_text.setFont(QFont("Consolas", 10))
        self.preview_table = QTableWidget(); self.tabs.addTab(self.summary_text, "Summary Report"); self.tabs.addTab(self.preview_table, "De-identified Data Preview")
        right_layout.addWidget(self.tabs)
        bottom_layout = QHBoxLayout(); save_csv_button = QPushButton("Save De-Identified File"); save_summary_button = QPushButton("Save Summary Report")
        save_csv_button.clicked.connect(self._save_deidentified); save_summary_button.clicked.connect(self._save_summary)
        bottom_layout.addWidget(save_csv_button); bottom_layout.addWidget(save_summary_button); bottom_layout.addStretch()
        right_layout.addLayout(bottom_layout); splitter.setSizes([550, 850])

    def _select_file(self):
        file_filter = "All Supported Files (*.csv *.txt *.pdf);;CSV Files (*.csv);;Text Files (*.txt);;PDF Files (*.pdf)"
        path, _ = QFileDialog.getOpenFileName(self, "Select Input File", "", file_filter)
        if path:
            self.input_path = path; self.input_file_type = os.path.splitext(path)[1].lower(); self.path_label.setText(os.path.basename(path)); self._clear_outputs()
            if self.input_file_type == '.pdf' and fitz is None:
                QMessageBox.critical(self, "Missing Library", "PyMuPDF is not installed. Please run 'pip install PyMuPDF' to process PDF files."); self.input_path = None

    def _run_detection(self):
        if not self.input_path: QMessageBox.warning(self, "No File", "Please select an input file first."); return
        self.run_button.setEnabled(False); self.progress_bar.setVisible(True); self._clear_outputs()
        mask_configs = self._get_mask_configs(); patterns = self._compile_overrides(); expected_counts = self._get_expected_counts()
        self.thread = QThread(); self.worker = Worker(self.input_path, patterns, mask_configs, expected_counts); self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run); self.worker.finished.connect(self._on_detection_complete)
        self.worker.error.connect(self._on_detection_error); self.worker.finished.connect(self.thread.quit); self.worker.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater); self.thread.start()

    def _on_detection_complete(self, result):
        self.headers, self.deidentified_rows, self.summary, self.report_metrics = result
        self._render_summary(); self._render_preview(); self.progress_bar.setVisible(False); self.run_button.setEnabled(True); QMessageBox.information(self, "Completed", "Detection and de-identification finished.")

    def _on_detection_error(self, err_msg):
        QMessageBox.critical(self, "Error", err_msg); self.progress_bar.setVisible(False); self.run_button.setEnabled(True)

    def _on_pattern_mode_change(self):
        self.preset_combo.setEnabled(self.preset_radio.isChecked()); self.custom_regex_widgets.setEnabled(not self.preset_radio.isChecked())

    def _get_mask_configs(self) -> Dict[str, Dict]:
        configs, s_map = {}, {"Partial Mask (Default)": "partial", "Full Mask": "full", "Hash (SHA256)": "hash", "Encryption": "encrypt", "Redact": "redact"}
        for key, widgets in self.mask_config_widgets.items():
            configs[key] = {"enabled": widgets["enabled"].isChecked(), "strategy": s_map.get(widgets["strategy"].currentText(), "partial"), "char": widgets["char"].text() or "*"}
        return configs
        
    def _get_expected_counts(self) -> Dict[str, Optional[int]]:
        return {key: int(w.text()) if w.text().isdigit() else None for key, w in self.expected_count_widgets.items()}

    def _compile_overrides(self) -> Dict[str, re.Pattern]:
        if self.preset_radio.isChecked(): return {}
        compiled = {}
        for key, widget in self.regex_widgets.items():
            pattern_text = widget.text().strip()
            if pattern_text:
                try: compiled[key] = re.compile(pattern_text)
                except re.error as e: QMessageBox.warning(self, "Regex Error", f"Invalid {self.pii_labels[key]} regex: {e}. It will be ignored.")
        return compiled

    def _render_summary(self):
        report = [f"--- Detection Summary Report ---\n", f"Rows Processed: {self.summary.get('rows_processed', 0)}\n"]
        header = f"{'PII Category':<20} | {'Found':<7} | {'Expected':<10} | {'TP':<5} | {'FP':<5} | {'Precision':<10} | {'Recall':<8} | {'F1-Score':<10} | {'Risk Level'}"
        report.append(header); report.append("-" * len(header))
        for key, metrics in self.report_metrics.items():
            expected_str = str(metrics['expected']) if metrics['expected'] is not None else 'N/A'
            line = (f"{self.pii_labels.get(key, key.title()):<20} | {metrics['found']:<7} | {expected_str:<10} | "
                    f"{metrics['tp']:<5} | {metrics['fp']:<5} | {metrics['precision']:<10.2f} | {metrics['recall']:<8.2f} | "
                    f"{metrics['f1']:<10.2f} | {metrics['risk']}")
            report.append(line)
        report.extend(["\n" + "="*40, "\n--- Accuracy Formulas ---\n", "Precision = TP / (TP + FP)  (Ability to avoid false positives)", "Recall    = TP / (TP + FN)     (Ability to find all positives)", "F1-Score  = 2 * (Precision * Recall) / (Precision + Recall)\n", "\n--- Risk Matrix ---\n", "Low:      All found items were expected (Precision = 1.0)", "Medium:   High precision (>= 0.8), few false positives.", "High:     Moderate precision (>= 0.5), some false positives.", "Critical: Low precision (< 0.5) or found items when none expected."])
        self.summary_text.setText("\n".join(report))

    def _render_preview(self):
        self.preview_table.setRowCount(len(self.deidentified_rows)); self.preview_table.setColumnCount(len(self.headers))
        self.preview_table.setHorizontalHeaderLabels(self.headers)
        for r, row_data in enumerate(self.deidentified_rows):
            for c, cell_data in enumerate(row_data): self.preview_table.setItem(r, c, QTableWidgetItem(cell_data))
        self.preview_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

    def _save_deidentified(self):
        if not self.deidentified_rows: QMessageBox.warning(self, "No Data", "No de-identified data to save."); return
        base_name = os.path.splitext(os.path.basename(self.input_path))[0] if self.input_path else "output"
        if self.input_file_type == '.csv':
            path, _ = QFileDialog.getSaveFileName(self, "Save De-Identified CSV", f"{base_name}_deidentified.csv", "CSV Files (*.csv)")
            if not path: return
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f);
                    if self.headers: writer.writerow(self.headers)
                    writer.writerows(self.deidentified_rows)
                QMessageBox.information(self, "Success", f"De-identified data saved to {path}")
            except Exception as e: QMessageBox.critical(self, "Error", f"Failed to save file: {e}")
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Save De-Identified Text File", f"{base_name}_deidentified.txt", "Text Files (*.txt)")
            if not path: return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    for row in self.deidentified_rows: f.write(row[0] + "\n")
                QMessageBox.information(self, "Success", f"De-identified text saved to {path}")
            except Exception as e: QMessageBox.critical(self, "Error", f"Failed to save file: {e}")

    def _save_summary(self):
        if not self.summary: QMessageBox.warning(self, "No Data", "No summary to save."); return
        path, _ = QFileDialog.getSaveFileName(self, "Save Summary Report", "summary_report.txt", "Text Files (*.txt)")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f: f.write(self.summary_text.toPlainText())
            QMessageBox.information(self, "Success", f"Summary report saved to {path}")
        except Exception as e: QMessageBox.critical(self, "Error", f"Failed to save summary: {e}")

    def _clear_outputs(self):
        self.deidentified_rows, self.headers, self.summary, self.report_metrics = [], [], {}, {}
        self.summary_text.clear(); self.preview_table.setRowCount(0); self.preview_table.setColumnCount(0)
    
    def closeEvent(self, event: QCloseEvent):
        """Handle the window close event to safely stop the worker thread."""
        if self.thread and self.thread.isRunning():
            reply = QMessageBox.question(self, 'Confirm Exit', 'A scan is in progress. Are you sure you want to exit?',
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                         QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.worker.stop()
                self.thread.quit()
                self.thread.wait(5000) # Wait up to 5 seconds
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PiiApp()
    window.show()
    sys.exit(app.exec())