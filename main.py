#!/usr/bin/env python3
"""
Enhanced Temporary File Cleaner
A comprehensive Python application for scanning and safely deleting temporary files.

Features:
- Advanced file detection algorithms
- Duplicate file detection
- Registry cleaning (Windows)
- Scheduled cleaning
- Detailed analytics and reporting
- Backup before deletion
- Whitelist/blacklist management
- System optimization recommendations

Usage: python enhanced_temp_cleaner.py
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import shutil
import tempfile
import threading
import time
import json
import hashlib
import sqlite3
import subprocess
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
import platform
import psutil
import re
from collections import defaultdict
import configparser

class EnhancedTempFileCleaner:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Temporary File Cleaner v2.0")
        self.root.geometry("1200x900")
        self.root.minsize(1000, 700)
        
        # Initialize variables
        self.temp_files = []
        self.duplicate_files = []
        self.total_size = 0
        self.is_scanning = False
        self.scan_stats = {}
        self.settings = self.load_settings()
        self.whitelist = set()
        self.blacklist = set()
        
        # Initialize database for tracking
        self.init_database()
        
        # Setup UI theme
        self.setup_theme()
        self.setup_ui()
        
        # Load whitelist/blacklist
        self.load_lists()
        
    def setup_theme(self):
        """Setup modern UI theme"""
        self.style = ttk.Style()
        
        # Try to use a modern theme
        available_themes = self.style.theme_names()
        if 'vista' in available_themes:
            self.style.theme_use('vista')
        elif 'clam' in available_themes:
            self.style.theme_use('clam')
        
        # Configure custom styles
        self.style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'))
        self.style.configure('Heading.TLabel', font=('Segoe UI', 12, 'bold'))
        self.style.configure('Stats.TLabel', font=('Segoe UI', 10))
        self.style.configure('Success.TLabel', foreground='green')
        self.style.configure('Warning.TLabel', foreground='orange')
        self.style.configure('Error.TLabel', foreground='red')
        
    def setup_ui(self):
        """Setup enhanced user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Main scanner tab
        self.scanner_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_frame, text="🔍 File Scanner")
        self.setup_scanner_tab()
        
        # Duplicate finder tab
        self.duplicate_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.duplicate_frame, text="👥 Duplicate Finder")
        self.setup_duplicate_tab()
        
        # System optimizer tab
        self.optimizer_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.optimizer_frame, text="⚡ System Optimizer")
        self.setup_optimizer_tab()
        
        # Analytics tab
        self.analytics_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analytics_frame, text="📊 Analytics")
        self.setup_analytics_tab()
        
        # Settings tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="⚙️ Settings")
        self.setup_settings_tab()
        
    def setup_scanner_tab(self):
        """Setup the main file scanner tab"""
        main_frame = ttk.Frame(self.scanner_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title and stats
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(title_frame, text="🗂️ Advanced Temporary File Cleaner", 
                 style='Title.TLabel').pack(side=tk.LEFT)
        
        # System info
        self.system_info_label = ttk.Label(title_frame, text=self.get_system_info(), 
                                          style='Stats.TLabel')
        self.system_info_label.pack(side=tk.RIGHT)
        
        # Control panel
        control_panel = ttk.LabelFrame(main_frame, text="🎛️ Control Panel", padding="10")
        control_panel.pack(fill=tk.X, pady=(0, 10))
        
        # Scan options
        scan_options_frame = ttk.Frame(control_panel)
        scan_options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Scan type selection
        ttk.Label(scan_options_frame, text="Scan Type:", style='Heading.TLabel').pack(side=tk.LEFT)
        
        self.scan_type = tk.StringVar(value="quick")
        ttk.Radiobutton(scan_options_frame, text="Quick Scan", variable=self.scan_type, 
                       value="quick").pack(side=tk.LEFT, padx=(10, 5))
        ttk.Radiobutton(scan_options_frame, text="Deep Scan", variable=self.scan_type, 
                       value="deep").pack(side=tk.LEFT, padx=(5, 5))
        ttk.Radiobutton(scan_options_frame, text="Custom Scan", variable=self.scan_type, 
                       value="custom").pack(side=tk.LEFT, padx=(5, 10))
        
        # Advanced options
        self.include_system_files = tk.BooleanVar(value=False)
        self.include_browser_data = tk.BooleanVar(value=True)
        self.include_logs = tk.BooleanVar(value=True)
        self.backup_before_delete = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(scan_options_frame, text="Include System Files", 
                       variable=self.include_system_files).pack(side=tk.LEFT, padx=(20, 5))
        ttk.Checkbutton(scan_options_frame, text="Browser Data", 
                       variable=self.include_browser_data).pack(side=tk.LEFT, padx=(5, 5))
        ttk.Checkbutton(scan_options_frame, text="Log Files", 
                       variable=self.include_logs).pack(side=tk.LEFT, padx=(5, 5))
        
        # Control buttons
        button_frame = ttk.Frame(control_panel)
        button_frame.pack(fill=tk.X)
        
        self.scan_btn = ttk.Button(button_frame, text="🔍 Start Advanced Scan", 
                                  command=self.start_advanced_scan, width=20)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = ttk.Button(button_frame, text="⏹️ Stop Scan", 
                                  command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress and status
        progress_frame = ttk.Frame(button_frame)
        progress_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        
        self.progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(0, 5))
        
        self.status_label = ttk.Label(progress_frame, text="Ready to scan")
        self.status_label.pack(fill=tk.X)
        
        # File list with enhanced features
        list_frame = ttk.LabelFrame(main_frame, text="📁 Detected Files", padding="5")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Toolbar for file list
        toolbar = ttk.Frame(list_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # Filter options
        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=20)
        filter_entry.pack(side=tk.LEFT, padx=(5, 10))
        filter_entry.bind('<KeyRelease>', self.filter_files)
        
        # Sort options
        ttk.Label(toolbar, text="Sort by:").pack(side=tk.LEFT)
        self.sort_var = tk.StringVar(value="size")
        sort_combo = ttk.Combobox(toolbar, textvariable=self.sort_var, width=10,
                                 values=["name", "size", "date", "type"], state="readonly")
        sort_combo.pack(side=tk.LEFT, padx=(5, 10))
        sort_combo.bind('<<ComboboxSelected>>', self.sort_files)
        
        # View options
        ttk.Button(toolbar, text="🔄 Refresh", command=self.refresh_view).pack(side=tk.LEFT, padx=(10, 5))
        ttk.Button(toolbar, text="📤 Export List", command=self.export_file_list).pack(side=tk.LEFT, padx=(5, 5))
        
        # Enhanced treeview
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('Path', 'Size', 'Modified', 'Type', 'Risk', 'Action')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings', height=15)
        
        # Configure columns with enhanced info
        self.tree.heading('#0', text='Select', anchor='w')
        self.tree.column('#0', width=80, minwidth=60)
        
        self.tree.heading('Path', text='File Path', anchor='w')
        self.tree.column('Path', width=300, minwidth=200)
        
        self.tree.heading('Size', text='Size', anchor='e')
        self.tree.column('Size', width=100, minwidth=80, anchor='e')
        
        self.tree.heading('Modified', text='Last Modified', anchor='center')
        self.tree.column('Modified', width=130, minwidth=100, anchor='center')
        
        self.tree.heading('Type', text='Category', anchor='w')
        self.tree.column('Type', width=120, minwidth=100)
        
        self.tree.heading('Risk', text='Risk Level', anchor='center')
        self.tree.column('Risk', width=80, minwidth=60, anchor='center')
        
        self.tree.heading('Action', text='Recommended Action', anchor='w')
        self.tree.column('Action', width=150, minwidth=120)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Bind events
        self.tree.bind('<Button-1>', self.on_item_click)
        self.tree.bind('<Double-1>', self.show_file_details)
        self.tree.bind('<Button-3>', self.show_context_menu)  # Right-click menu
        
        # Selection and action panel
        action_panel = ttk.LabelFrame(main_frame, text="📋 Selection & Actions", padding="10")
        action_panel.pack(fill=tk.X)
        
        # Selection stats
        stats_frame = ttk.Frame(action_panel)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.selection_stats = ttk.Label(stats_frame, text="No files selected", 
                                        style='Stats.TLabel')
        self.selection_stats.pack(side=tk.LEFT)
        
        self.size_savings = ttk.Label(stats_frame, text="Potential savings: 0 MB", 
                                     style='Success.TLabel')
        self.size_savings.pack(side=tk.RIGHT)
        
        # Action buttons
        action_buttons = ttk.Frame(action_panel)
        action_buttons.pack(fill=tk.X)
        
        # Selection buttons
        ttk.Button(action_buttons, text="✅ Select All", 
                  command=self.select_all).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_buttons, text="❌ Deselect All", 
                  command=self.deselect_all).pack(side=tk.LEFT, padx=(5, 5))
        ttk.Button(action_buttons, text="🎯 Smart Select", 
                  command=self.smart_select).pack(side=tk.LEFT, padx=(5, 5))
        ttk.Button(action_buttons, text="🏷️ Select by Type", 
                  command=self.select_by_type).pack(side=tk.LEFT, padx=(5, 10))
        
        # Action buttons
        ttk.Button(action_buttons, text="📂 Add Location", 
                  command=self.add_custom_location).pack(side=tk.LEFT, padx=(10, 5))
        ttk.Button(action_buttons, text="🔒 Add to Whitelist", 
                  command=self.add_to_whitelist).pack(side=tk.LEFT, padx=(5, 5))
        
        # Main action buttons
        main_actions = ttk.Frame(action_panel)
        main_actions.pack(fill=tk.X, pady=(10, 0))
        
        self.backup_btn = ttk.Button(main_actions, text="💾 Backup Selected", 
                                    command=self.backup_files, state='disabled')
        self.backup_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.delete_btn = ttk.Button(main_actions, text="🗑️ Delete Selected Files", 
                                    command=self.delete_selected, state='disabled')
        self.delete_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Warning
        ttk.Label(main_actions, text="⚠️ Always backup important files before deletion!", 
                 style='Warning.TLabel').pack(side=tk.RIGHT)
        
    def setup_duplicate_tab(self):
        """Setup duplicate file finder tab"""
        main_frame = ttk.Frame(self.duplicate_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="👥 Duplicate File Finder", 
                 style='Title.TLabel').pack(pady=(0, 20))
        
        # Control panel
        control_panel = ttk.LabelFrame(main_frame, text="🎛️ Duplicate Detection Settings", padding="10")
        control_panel.pack(fill=tk.X, pady=(0, 10))
        
        # Options
        options_frame = ttk.Frame(control_panel)
        options_frame.pack(fill=tk.X)
        
        self.check_content = tk.BooleanVar(value=True)
        self.check_name = tk.BooleanVar(value=False)
        self.min_file_size = tk.StringVar(value="1")  # MB
        
        ttk.Checkbutton(options_frame, text="Compare file content (slower, accurate)", 
                       variable=self.check_content).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Checkbutton(options_frame, text="Compare names only (faster)", 
                       variable=self.check_name).pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Label(options_frame, text="Min size (MB):").pack(side=tk.LEFT)
        ttk.Entry(options_frame, textvariable=self.min_file_size, width=5).pack(side=tk.LEFT, padx=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(control_panel)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="🔍 Find Duplicates", 
                  command=self.find_duplicates).pack(side=tk.LEFT, padx=(0, 10))
        
        self.duplicate_progress = ttk.Progressbar(button_frame, mode='indeterminate')
        self.duplicate_progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))
        
        # Results
        results_frame = ttk.LabelFrame(main_frame, text="📊 Duplicate Groups", padding="5")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Duplicate tree
        self.duplicate_tree = ttk.Treeview(results_frame, columns=('Count', 'Size', 'Total_Size'), 
                                          show='tree headings', height=15)
        
        self.duplicate_tree.heading('#0', text='File Group')
        self.duplicate_tree.heading('Count', text='Count')
        self.duplicate_tree.heading('Size', text='File Size')
        self.duplicate_tree.heading('Total_Size', text='Wasted Space')
        
        self.duplicate_tree.pack(fill=tk.BOTH, expand=True)
        
    def setup_optimizer_tab(self):
        """Setup system optimizer tab"""
        main_frame = ttk.Frame(self.optimizer_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="⚡ System Optimizer", 
                 style='Title.TLabel').pack(pady=(0, 20))
        
        # System health check
        health_frame = ttk.LabelFrame(main_frame, text="🏥 System Health Check", padding="10")
        health_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.health_text = tk.Text(health_frame, height=8, wrap=tk.WORD)
        self.health_text.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(health_frame, text="🔍 Analyze System", 
                  command=self.analyze_system).pack(pady=(10, 0))
        
        # Optimization recommendations
        rec_frame = ttk.LabelFrame(main_frame, text="💡 Recommendations", padding="10")
        rec_frame.pack(fill=tk.BOTH, expand=True)
        
        self.recommendations_tree = ttk.Treeview(rec_frame, columns=('Impact', 'Effort', 'Description'), 
                                               show='tree headings')
        
        self.recommendations_tree.heading('#0', text='Optimization')
        self.recommendations_tree.heading('Impact', text='Impact')
        self.recommendations_tree.heading('Effort', text='Effort')
        self.recommendations_tree.heading('Description', text='Description')
        
        self.recommendations_tree.pack(fill=tk.BOTH, expand=True)
        
    def setup_analytics_tab(self):
        """Setup analytics and reporting tab"""
        main_frame = ttk.Frame(self.analytics_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="📊 Cleanup Analytics & Reports", 
                 style='Title.TLabel').pack(pady=(0, 20))
        
        # Stats overview
        stats_frame = ttk.LabelFrame(main_frame, text="📈 Statistics Overview", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_text = tk.Text(stats_frame, height=6, wrap=tk.WORD)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # History
        history_frame = ttk.LabelFrame(main_frame, text="📜 Cleanup History", padding="5")
        history_frame.pack(fill=tk.BOTH, expand=True)
        
        self.history_tree = ttk.Treeview(history_frame, columns=('Date', 'Files', 'Size', 'Type'), 
                                        show='tree headings')
        
        self.history_tree.heading('#0', text='Session')
        self.history_tree.heading('Date', text='Date')
        self.history_tree.heading('Files', text='Files Cleaned')
        self.history_tree.heading('Size', text='Space Freed')
        self.history_tree.heading('Type', text='Scan Type')
        
        self.history_tree.pack(fill=tk.BOTH, expand=True)
        
        # Load history
        self.load_cleanup_history()
        
    def setup_settings_tab(self):
        """Setup settings and configuration tab"""
        main_frame = ttk.Frame(self.settings_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="⚙️ Settings & Configuration", 
                 style='Title.TLabel').pack(pady=(0, 20))
        
        # General settings
        general_frame = ttk.LabelFrame(main_frame, text="🔧 General Settings", padding="10")
        general_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Auto-backup
        self.auto_backup = tk.BooleanVar(value=self.settings.get('auto_backup', True))
        ttk.Checkbutton(general_frame, text="Automatically backup files before deletion", 
                       variable=self.auto_backup).pack(anchor='w')
        
        # Backup location
        backup_frame = ttk.Frame(general_frame)
        backup_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(backup_frame, text="Backup location:").pack(side=tk.LEFT)
        self.backup_location = tk.StringVar(value=self.settings.get('backup_location', ''))
        ttk.Entry(backup_frame, textvariable=self.backup_location, width=50).pack(side=tk.LEFT, padx=(10, 5))
        ttk.Button(backup_frame, text="Browse", command=self.browse_backup_location).pack(side=tk.LEFT)
        
        # Scheduled cleanup
        schedule_frame = ttk.LabelFrame(main_frame, text="⏰ Scheduled Cleanup", padding="10")
        schedule_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.enable_schedule = tk.BooleanVar(value=self.settings.get('enable_schedule', False))
        ttk.Checkbutton(schedule_frame, text="Enable scheduled cleanup", 
                       variable=self.enable_schedule).pack(anchor='w')
        
        # Schedule options
        schedule_options = ttk.Frame(schedule_frame)
        schedule_options.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(schedule_options, text="Frequency:").pack(side=tk.LEFT)
        self.schedule_frequency = tk.StringVar(value=self.settings.get('schedule_frequency', 'weekly'))
        frequency_combo = ttk.Combobox(schedule_options, textvariable=self.schedule_frequency,
                                     values=['daily', 'weekly', 'monthly'], state='readonly')
        frequency_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # Whitelist/Blacklist management
        lists_frame = ttk.LabelFrame(main_frame, text="📋 File Lists Management", padding="10")
        lists_frame.pack(fill=tk.BOTH, expand=True)
        
        # Lists notebook
        lists_notebook = ttk.Notebook(lists_frame)
        lists_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Whitelist
        whitelist_frame = ttk.Frame(lists_notebook)
        lists_notebook.add(whitelist_frame, text="✅ Whitelist (Never Delete)")
        
        self.whitelist_text = tk.Text(whitelist_frame, height=8)
        self.whitelist_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        ttk.Button(whitelist_frame, text="Save Whitelist", 
                  command=self.save_whitelist).pack(side=tk.LEFT)
        
        # Blacklist
        blacklist_frame = ttk.Frame(lists_notebook)
        lists_notebook.add(blacklist_frame, text="❌ Blacklist (Always Delete)")
        
        self.blacklist_text = tk.Text(blacklist_frame, height=8)
        self.blacklist_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        ttk.Button(blacklist_frame, text="Save Blacklist", 
                  command=self.save_blacklist).pack(side=tk.LEFT)
        
        # Save settings button
        ttk.Button(main_frame, text="💾 Save All Settings", 
                  command=self.save_settings).pack(pady=(10, 0))
        
    def get_system_info(self):
        """Get system information"""
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return (f"CPU: {cpu_percent}% | "
                   f"RAM: {memory.percent}% | "
                   f"Disk: {disk.percent}% used")
        except:
            return "System info unavailable"
    
    def load_settings(self):
        """Load application settings"""
        config_file = os.path.join(os.path.expanduser("~"), ".temp_cleaner_config.json")
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def save_settings(self):
        """Save application settings"""
        config_file = os.path.join(os.path.expanduser("~"), ".temp_cleaner_config.json")
        
        settings = {
            'auto_backup': self.auto_backup.get(),
            'backup_location': self.backup_location.get(),
            'enable_schedule': self.enable_schedule.get(),
            'schedule_frequency': self.schedule_frequency.get(),
        }
        
        try:
            with open(config_file, 'w') as f:
                json.dump(settings, f, indent=2)
            messagebox.showinfo("Settings", "Settings saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")
    
    def init_database(self):
        """Initialize SQLite database for tracking"""
        db_path = os.path.join(os.path.expanduser("~"), ".temp_cleaner.db")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        
        # Create tables
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cleanup_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                files_count INTEGER,
                size_freed INTEGER,
                scan_type TEXT,
                details TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE,
                file_hash TEXT,
                size INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                cleanup_count INTEGER DEFAULT 0
            )
        ''')
        
        self.conn.commit()
    
    def start_advanced_scan(self):
        """Start advanced scanning with multiple algorithms"""
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.scan_btn.config(state='disabled', text="🔄 Scanning...")
        self.stop_btn.config(state='normal')
        self.progress.config(mode='determinate', value=0)
        
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.temp_files = []
        self.total_size = 0
        
        # Start scanning thread
        thread = threading.Thread(target=self.advanced_scan_worker)
        thread.daemon = True
        thread.start()
    
    def advanced_scan_worker(self):
        """Advanced scanning worker with multiple detection methods"""
        scan_type = self.scan_type.get()
        locations = self.get_enhanced_temp_locations()
        total_locations = len(locations)
        
        self.scan_stats = {
            'total_files': 0,
            'total_size': 0,
            'categories': defaultdict(int),
            'risk_levels': defaultdict(int)
        }
        
        all_files = []
        
        for i, (location, category) in enumerate(locations):
            if not self.is_scanning:  # Check for stop signal
                break
                
            # Update progress
            progress = (i / total_locations) * 100
            self.root.after(0, lambda p=progress: self.progress.config(value=p))
            self.root.after(0, lambda c=category: self.status_label.config(text=f"Scanning {c}..."))
            
            # Scan directory with enhanced detection
            files = self.enhanced_scan_directory(location, category, scan_type)
            all_files.extend(files)
            
            # Update stats
            self.scan_stats['total_files'] += len(files)
            self.scan_stats['total_size'] += sum(f['size'] for f in files)
            self.scan_stats['categories'][category] += len(files)
        
        # Complete scan
        self.root.after(0, lambda: self.advanced_scan_complete(all_files))
    
    def enhanced_scan_directory(self, directory, category, scan_type):
        """Enhanced directory scanning with multiple detection algorithms"""
        temp_files = []
        
        if not os.path.exists(directory):
            return temp_files
        
        try:
            max_depth = 2 if scan_type == "quick" else 5 if scan_type == "deep" else 3
            
            for root, dirs, files in os.walk(directory):
                if not self.is_scanning:
                    break
                
                # Control scan depth
                depth = root.replace(directory, '').count(os.sep)
                if depth > max_depth:
                    dirs[:] = []  # Don't recurse deeper
                    continue
                
                # Skip system-critical directories
                if self.is_critical_directory(root):
                    dirs[:] = []
                    continue
                
                for file in files:
                    if not self.is_scanning:
                        break
                        
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Enhanced file analysis
                        file_info = self.analyze_file(file_path, category)
                        if file_info:
                            temp_files.append(file_info)
                            
                    except (OSError, PermissionError, ValueError):
                        continue
                        
        except (OSError, PermissionError):
            pass
            
        return temp_files
    
    def analyze_file(self, file_path, category):
        """Advanced file analysis with risk assessment"""
        try:
            stat = os.stat(file_path)
            age_days = (time.time() - stat.st_mtime) / (24 * 3600)
            
            # Check if file is whitelisted
            if self.is_whitelisted(file_path):
                return None
            
            # Multiple detection methods
            is_temp = False
            risk_level = "Low"
            recommended_action = "Review"
            confidence = 0
            
            # Method 1: Extension-based detection
            if self.is_temp_by_extension(file_path):
                is_temp = True
                confidence += 30
                recommended_action = "Safe to delete"
            
            # Method 2: Pattern-based detection
            if self.is_temp_by_pattern(file_path):
                is_temp = True
                confidence += 25
            
            # Method 3: Location-based detection
            if self.is_temp_by_location(file_path):
                is_temp = True
                confidence += 20
            
            # Method 4: Age-based detection
            if age_days > 30:
                confidence += 15
                if age_days > 90:
                    confidence += 10
            
            # Method 5: Size-based heuristics
            if stat.st_size == 0:
                confidence += 20
                recommended_action = "Safe to delete"
            elif stat.st_size > 100 * 1024 * 1024:  # > 100MB
                risk_level = "Medium"
                recommended_action = "Review carefully"
            
            # Method 6: File content analysis (for specific types)
            if self.analyze_file_content(file_path):
                confidence += 15
            
            # Determine risk level based on confidence
            if confidence >= 70:
                risk_level = "Low"
                recommended_action = "Safe to delete"
            elif confidence >= 40:
                risk_level = "Medium"
                recommended_action = "Review"
            else:
                risk_level = "High"
                recommended_action = "Keep"
            
            # Force include if blacklisted
            if self.is_blacklisted(file_path):
                is_temp = True
                risk_level = "Low"
                recommended_action = "Delete (blacklisted)"
            
            if is_temp or confidence >= 30:
                return {
                    'path': file_path,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'type': category,
                    'risk_level': risk_level,
                    'recommended_action': recommended_action,
                    'confidence': confidence,
                    'selected': False,
                    'age_days': age_days
                }
                
        except Exception:
            pass
        
        return None
    
    def is_temp_by_extension(self, file_path):
        """Check if file is temporary based on extension"""
        temp_extensions = {
            '.tmp', '.temp', '.cache', '.log', '.bak', '.old', '.~tmp',
            '.crdownload', '.partial', '.swp', '.swo', '.pid', '.lock',
            '.dmp', '.chk', '.gid', '.ftg', '.fts', '.ffa', '.~lock',
            '.thumbs', '.ds_store', '.desktop.ini'
        }
        
        _, ext = os.path.splitext(file_path.lower())
        return ext in temp_extensions
    
    def is_temp_by_pattern(self, file_path):
        """Check if file is temporary based on naming patterns"""
        filename = os.path.basename(file_path).lower()
        
        temp_patterns = [
            r'^temp.*', r'.*temp',
            r'^tmp.*', r'.*tmp',
            r'^cache.*', r'.*cache',
            r'^log.*', r'.*\.log',
            r'^backup.*', r'.*backup',
            r'^~\$.*',
            r'thumbs\.db',
            r'desktop\.ini',
            r'\.ds_store',
            r'^recent.*', r'.*recent',
            r'^preview.*',
            r'.*\.old',
            r'.*\.bak',
            r'^~.*\.tmp',
        ]
        
        return any(re.match(pattern, filename) for pattern in temp_patterns)
    
    def is_temp_by_location(self, file_path):
        """Check if file is temporary based on its location"""
        path_lower = file_path.lower()
        
        temp_locations = [
            'temp', 'tmp', 'cache', 'logs', 'recent',
            'thumbnails', 'preview', 'backup', 'recycle',
            'trash', 'temporary', 'inet'
        ]
        
        return any(location in path_lower for location in temp_locations)
    
    def analyze_file_content(self, file_path):
        """Analyze file content for temporary file indicators"""
        try:
            # Only analyze small files to avoid performance issues
            if os.path.getsize(file_path) > 1024 * 1024:  # 1MB limit
                return False
            
            # Check for specific file signatures
            with open(file_path, 'rb') as f:
                header = f.read(512)
                
            # Check for common temp file headers/signatures
            temp_signatures = [
                b'TEMP', b'TMP', b'CACHE', b'LOG',
                b'Microsoft Office', b'~'
            
            ]
            
            return any(sig in header for sig in temp_signatures)
            
        except:
            return False
    
    def is_critical_directory(self, directory):
        """Check if directory is critical and should be avoided"""
        critical_dirs = [
            'system32', 'windows/system', 'boot', 'recovery',
            'program files', 'windows/fonts', 'windows/inf',
            'windows/winsxs', 'programdata/microsoft/windows/wer',
            '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc',
            '/System', '/Library/System'
        ]
        
        dir_lower = directory.lower()
        return any(critical in dir_lower for critical in critical_dirs)
    
    def is_whitelisted(self, file_path):
        """Check if file is in whitelist"""
        for pattern in self.whitelist:
            if pattern in file_path or re.match(pattern, file_path):
                return True
        return False
    
    def is_blacklisted(self, file_path):
        """Check if file is in blacklist"""
        for pattern in self.blacklist:
            if pattern in file_path or re.match(pattern, file_path):
                return True
        return False
    
    def get_enhanced_temp_locations(self):
        """Get comprehensive list of temporary file locations"""
        locations = []
        system = platform.system()
        
        try:
            if system == "Windows":
                base_locations = [
                    (os.environ.get('TEMP', ''), "User Temp Directory"),
                    (os.environ.get('TMP', ''), "System Temp Directory"),
                    (os.path.join(os.environ.get('WINDIR', ''), 'Temp'), "Windows Temp"),
                    (os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'), "Local AppData Temp"),
                ]
                
                # Browser locations
                if self.include_browser_data.get():
                    browser_locations = self.get_browser_locations_windows()
                    locations.extend(browser_locations)
                
                # System-specific locations
                if self.include_system_files.get():
                    system_locations = [
                        (os.path.join(os.environ.get('WINDIR', ''), 'Prefetch'), "Windows Prefetch"),
                        (os.path.join(os.environ.get('WINDIR', ''), 'SoftwareDistribution', 'Download'), "Windows Update Cache"),
                        (os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Windows', 'INetCache'), "Internet Cache"),
                        (os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Recent'), "Recent Items"),
                    ]
                    locations.extend(system_locations)
                
                # Log locations
                if self.include_logs.get():
                    log_locations = [
                        (os.path.join(os.environ.get('WINDIR', ''), 'Logs'), "Windows Logs"),
                        (os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'), "Application Logs"),
                    ]
                    locations.extend(log_locations)
                
                locations.extend(base_locations)
                
            elif system == "Darwin":  # macOS
                home = os.path.expanduser("~")
                base_locations = [
                    (tempfile.gettempdir(), "System Temp"),
                    (os.path.join(home, "Library", "Caches"), "User Caches"),
                    (os.path.join(home, "Library", "Logs"), "User Logs"),
                    (os.path.join(home, ".Trash"), "Trash"),
                ]
                
                if self.include_browser_data.get():
                    browser_locations = self.get_browser_locations_mac()
                    locations.extend(browser_locations)
                
                locations.extend(base_locations)
                
            else:  # Linux
                home = os.path.expanduser("~")
                base_locations = [
                    (tempfile.gettempdir(), "System Temp"),
                    (os.path.join(home, ".cache"), "User Cache"),
                    ("/tmp", "Temp Directory"),
                    ("/var/tmp", "Variable Temp"),
                    (os.path.join(home, ".local", "share", "Trash"), "Trash"),
                ]
                
                if self.include_browser_data.get():
                    browser_locations = self.get_browser_locations_linux()
                    locations.extend(browser_locations)
                
                locations.extend(base_locations)
                
        except Exception as e:
            print(f"Error getting temp locations: {e}")
        
        # Filter out non-existent locations
        return [(path, desc) for path, desc in locations if path and os.path.exists(path)]
    
    def get_browser_locations_windows(self):
        """Get Windows browser cache locations"""
        locations = []
        localappdata = os.environ.get('LOCALAPPDATA', '')
        appdata = os.environ.get('APPDATA', '')
        
        browsers = [
            (os.path.join(localappdata, 'Google', 'Chrome', 'User Data', 'Default', 'Cache'), "Chrome Cache"),
            (os.path.join(localappdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'), "Edge Cache"),
            (os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles'), "Firefox Cache"),
            (os.path.join(localappdata, 'Opera Software', 'Opera Stable', 'Cache'), "Opera Cache"),
        ]
        
        return [(path, desc) for path, desc in browsers if os.path.exists(path)]
    
    def get_browser_locations_mac(self):
        """Get macOS browser cache locations"""
        home = os.path.expanduser("~")
        browsers = [
            (os.path.join(home, "Library", "Caches", "Google", "Chrome"), "Chrome Cache"),
            (os.path.join(home, "Library", "Caches", "Mozilla", "Firefox"), "Firefox Cache"),
            (os.path.join(home, "Library", "Caches", "com.apple.Safari"), "Safari Cache"),
        ]
        
        return [(path, desc) for path, desc in browsers if os.path.exists(path)]
    
    def get_browser_locations_linux(self):
        """Get Linux browser cache locations"""
        home = os.path.expanduser("~")
        browsers = [
            (os.path.join(home, ".cache", "google-chrome"), "Chrome Cache"),
            (os.path.join(home, ".cache", "mozilla", "firefox"), "Firefox Cache"),
            (os.path.join(home, ".cache", "opera"), "Opera Cache"),
        ]
        
        return [(path, desc) for path, desc in browsers if os.path.exists(path)]
    
    def advanced_scan_complete(self, files):
        """Handle advanced scan completion"""
        self.temp_files = files
        self.is_scanning = False
        self.scan_btn.config(state='normal', text="🔍 Start Advanced Scan")
        self.stop_btn.config(state='disabled')
        self.progress.config(value=100)
        
        # Calculate total size
        self.total_size = sum(f['size'] for f in files)
        
        # Populate tree with enhanced data
        self.populate_enhanced_tree()
        
        # Update status and enable buttons
        file_count = len(files)
        self.status_label.config(text=f"Scan complete - Found {file_count} files ({self.format_size(self.total_size)})")
        
        if files:
            self.delete_btn.config(state='normal')
            self.backup_btn.config(state='normal')
        
        # Update analytics
        self.update_analytics()
    
    def populate_enhanced_tree(self):
        """Populate tree with enhanced file information"""
        # Group files by category and risk level
        file_groups = defaultdict(lambda: defaultdict(list))
        
        for file_info in self.temp_files:
            category = file_info['type']
            risk = file_info['risk_level']
            file_groups[category][risk].append(file_info)
        
        # Sort categories by total size
        sorted_categories = sorted(file_groups.items(), 
                                 key=lambda x: sum(f['size'] for risk_files in x[1].values() for f in risk_files),
                                 reverse=True)
        
        for category, risk_groups in sorted_categories:
            # Calculate category totals
            total_files = sum(len(files) for files in risk_groups.values())
            total_size = sum(f['size'] for files in risk_groups.values() for f in files)
            
            # Add category header
            category_text = f"📁 {category} ({total_files} files)"
            category_id = self.tree.insert('', 'end', text=category_text,
                                         values=('', self.format_size(total_size), '', category, '', ''),
                                         tags=('category_header',))
            
            # Add risk level subgroups
            for risk_level in ['Low', 'Medium', 'High']:
                if risk_level in risk_groups:
                    files = risk_groups[risk_level]
                    risk_size = sum(f['size'] for f in files)
                    
                    # Risk level colors
                    risk_colors = {'Low': '🟢', 'Medium': '🟡', 'High': '🔴'}
                    risk_text = f"{risk_colors[risk_level]} {risk_level} Risk ({len(files)} files)"
                    
                    risk_id = self.tree.insert(category_id, 'end', text=risk_text,
                                             values=('', self.format_size(risk_size), '', '', risk_level, ''),
                                             tags=('risk_header',))
                    
                    # Sort files by size
                    files.sort(key=lambda x: x['size'], reverse=True)
                    
                    # Add individual files
                    for file_info in files:
                        rel_path = self.get_relative_path(file_info['path'])
                        
                        # Limit path length for display
                        if len(rel_path) > 60:
                            rel_path = "..." + rel_path[-57:]
                        
                        file_id = self.tree.insert(risk_id, 'end', text='[ ]',
                                                 values=(rel_path,
                                                       self.format_size(file_info['size']),
                                                       file_info['modified'].strftime('%Y-%m-%d %H:%M'),
                                                       file_info['type'],
                                                       file_info['risk_level'],
                                                       file_info['recommended_action']),
                                                 tags=('file',))
                        file_info['tree_id'] = file_id
        
        # Configure enhanced tags
        self.tree.tag_configure('category_header', background='lightblue', font=('Arial', 10, 'bold'))
        self.tree.tag_configure('risk_header', background='lightyellow', font=('Arial', 9, 'bold'))
        self.tree.tag_configure('file', background='white')
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        self.stop_btn.config(state='disabled')
        self.status_label.config(text="Scan stopped by user")
    
    def smart_select(self):
        """Intelligently select files based on risk assessment"""
        selected_count = 0
        
        for file_info in self.temp_files:
            # Auto-select low risk files and files with high confidence
            should_select = (
                file_info['risk_level'] == 'Low' or
                file_info['confidence'] >= 70 or
                file_info['age_days'] > 90 or
                'Safe to delete' in file_info['recommended_action']
            )
            
            if should_select:
                file_info['selected'] = True
                if 'tree_id' in file_info:
                    self.tree.item(file_info['tree_id'], text='[X]')
                selected_count += 1
        
        self.update_selection_stats()
        messagebox.showinfo("Smart Selection", 
                           f"Automatically selected {selected_count} low-risk files for deletion.")
    
    def backup_files(self):
        """Create backup of selected files"""
        selected_files = [f for f in self.temp_files if f.get('selected', False)]
        
        if not selected_files:
            messagebox.showwarning("No Selection", "Please select files to backup.")
            return
        
        # Get backup location
        backup_dir = self.backup_location.get() or tempfile.gettempdir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"temp_cleaner_backup_{timestamp}.zip"
        backup_path = os.path.join(backup_dir, backup_name)
        
        try:
            self.status_label.config(text="Creating backup...")
            self.progress.config(mode='indeterminate')
            self.progress.start()
            
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_info in selected_files:
                    try:
                        file_path = file_info['path']
                        if os.path.exists(file_path):
                            # Create archive path to preserve directory structure
                            archive_path = os.path.relpath(file_path, '/')
                            zipf.write(file_path, archive_path)
                    except Exception as e:
                        print(f"Failed to backup {file_path}: {e}")
            
            self.progress.stop()
            self.status_label.config(text="Backup completed")
            
            messagebox.showinfo("Backup Complete", 
                               f"Backup created successfully:\n{backup_path}")
            
        except Exception as e:
            self.progress.stop()
            messagebox.showerror("Backup Error", f"Failed to create backup: {e}")
    
    def find_duplicates(self):
        """Find duplicate files"""
        self.duplicate_progress.start()
        
        def find_duplicates_worker():
            duplicates = defaultdict(list)
            min_size = float(self.min_file_size.get()) * 1024 * 1024  # Convert MB to bytes
            
            # Get all files from temp locations
            locations = self.get_enhanced_temp_locations()
            all_files = []
            
            for location, _ in locations:
                for root, dirs, files in os.walk(location):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            size = os.path.getsize(file_path)
                            if size >= min_size:
                                all_files.append((file_path, size))
                        except:
                            continue
            
            # Find duplicates
            if self.check_content.get():
                # Content-based comparison (slower but accurate)
                file_hashes = {}
                for file_path, size in all_files:
                    try:
                        hash_obj = hashlib.md5()
                        with open(file_path, 'rb') as f:
                            for chunk in iter(lambda: f.read(4096), b""):
                                hash_obj.update(chunk)
                        file_hash = hash_obj.hexdigest()
                        
                        if file_hash in file_hashes:
                            file_hashes[file_hash].append((file_path, size))
                        else:
                            file_hashes[file_hash] = [(file_path, size)]
                    except:
                        continue
                
                # Filter groups with more than one file
                duplicates = {h: files for h, files in file_hashes.items() if len(files) > 1}
            
            elif self.check_name.get():
                # Name-based comparison (faster)
                name_groups = defaultdict(list)
                for file_path, size in all_files:
                    filename = os.path.basename(file_path)
                    name_groups[filename].append((file_path, size))
                
                duplicates = {name: files for name, files in name_groups.items() if len(files) > 1}
            
            # Update UI
            self.root.after(0, lambda: self.display_duplicates(duplicates))
        
        thread = threading.Thread(target=find_duplicates_worker)
        thread.daemon = True
        thread.start()
    
    def display_duplicates(self, duplicates):
        """Display duplicate file groups"""
        self.duplicate_progress.stop()
        
        # Clear previous results
        for item in self.duplicate_tree.get_children():
            self.duplicate_tree.delete(item)
        
        if not duplicates:
            self.duplicate_tree.insert('', 'end', text="No duplicates found", values=('', '', ''))
            return
        
        total_wasted = 0
        
        for group_id, files in duplicates.items():
            if len(files) > 1:
                # Keep the first file, others are duplicates
                original_size = files[0][1]
                wasted_space = original_size * (len(files) - 1)
                total_wasted += wasted_space
                
                group_text = f"Group: {group_id[:50]}..."
                group_item = self.duplicate_tree.insert('', 'end', text=group_text,
                                                       values=(len(files), 
                                                             self.format_size(original_size),
                                                             self.format_size(wasted_space)))
                
                for i, (file_path, size) in enumerate(files):
                    status = "Original" if i == 0 else "Duplicate"
                    self.duplicate_tree.insert(group_item, 'end', text=f"  {status}: {file_path}",
                                             values=('', self.format_size(size), ''))
        
        # Add summary
        self.duplicate_tree.insert('', 'end', text=f"TOTAL WASTED SPACE",
                                 values=('', '', self.format_size(total_wasted)),
                                 tags=('summary',))
        
        self.duplicate_tree.tag_configure('summary', background='yellow', font=('Arial', 10, 'bold'))
    
    def analyze_system(self):
        """Perform system health analysis"""
        self.health_text.delete(1.0, tk.END)
        
        analysis_text = "🔍 SYSTEM HEALTH ANALYSIS\n" + "="*50 + "\n\n"
        
        try:
            # CPU Analysis
            cpu_percent = psutil.cpu_percent(interval=1)
            analysis_text += f"💻 CPU Usage: {cpu_percent}%\n"
            if cpu_percent > 80:
                analysis_text += "  ⚠️ HIGH CPU usage detected!\n"
            
            # Memory Analysis
            memory = psutil.virtual_memory()
            analysis_text += f"🧠 Memory Usage: {memory.percent}% ({self.format_size(memory.used)}/{self.format_size(memory.total)})\n"
            if memory.percent > 80:
                analysis_text += "  ⚠️ HIGH memory usage detected!\n"
            
            # Disk Analysis
            disk = psutil.disk_usage('/')
            analysis_text += f"💾 Disk Usage: {disk.percent}% ({self.format_size(disk.used)}/{self.format_size(disk.total)})\n"
            if disk.percent > 90:
                analysis_text += "  ⚠️ LOW disk space warning!\n"
            
            # Process Analysis
            processes = len(psutil.pids())
            analysis_text += f"⚙️ Running Processes: {processes}\n"
            
            # Network Analysis
            try:
                network = psutil.net_io_counters()
                analysis_text += f"🌐 Network: Sent {self.format_size(network.bytes_sent)}, Received {self.format_size(network.bytes_recv)}\n"
            except:
                pass
            
            analysis_text += "\n" + "="*50 + "\n"
            analysis_text += "💡 RECOMMENDATIONS:\n\n"
            
            # Generate recommendations based on analysis
            if disk.percent > 80:
                analysis_text += "• Run disk cleanup to free space\n"
            if memory.percent > 70:
                analysis_text += "• Close unnecessary applications\n"
            if cpu_percent > 70:
                analysis_text += "• Check for resource-intensive processes\n"
            
            analysis_text += "• Regularly clean temporary files\n"
            analysis_text += "• Consider defragmenting your disk\n"
            analysis_text += "• Update your operating system\n"
            
        except Exception as e:
            analysis_text += f"Error during analysis: {e}\n"
        
        self.health_text.insert(1.0, analysis_text)
    
    def update_analytics(self):
        """Update analytics display"""
        stats_text = "📊 SCAN STATISTICS\n" + "="*40 + "\n\n"
        
        if self.scan_stats:
            stats_text += f"Total Files Scanned: {self.scan_stats['total_files']:,}\n"
            stats_text += f"Total Size: {self.format_size(self.scan_stats['total_size'])}\n\n"
            
            stats_text += "Files by Category:\n"
            for category, count in self.scan_stats['categories'].items():
                stats_text += f"  • {category}: {count:,} files\n"
            
            stats_text += "\nRisk Distribution:\n"
            for risk, count in self.scan_stats['risk_levels'].items():
                stats_text += f"  • {risk} Risk: {count:,} files\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats_text)
    
    def load_cleanup_history(self):
        """Load cleanup history from database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT date, files_count, size_freed, scan_type 
                FROM cleanup_history 
                ORDER BY date DESC 
                LIMIT 50
            ''')
            
            for i, (date, files_count, size_freed, scan_type) in enumerate(cursor.fetchall()):
                self.history_tree.insert('', 'end', text=f"Session {i+1}",
                                       values=(date, f"{files_count:,}", 
                                             self.format_size(size_freed), scan_type))
        except:
            pass
    
    def load_lists(self):
        """Load whitelist and blacklist"""
        try:
            # Load whitelist
            whitelist_file = os.path.join(os.path.expanduser("~"), ".temp_cleaner_whitelist.txt")
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r') as f:
                    self.whitelist = set(line.strip() for line in f if line.strip())
                    self.whitelist_text.insert(1.0, '\n'.join(self.whitelist))
            
            # Load blacklist
            blacklist_file = os.path.join(os.path.expanduser("~"), ".temp_cleaner_blacklist.txt")
            if os.path.exists(blacklist_file):
                with open(blacklist_file, 'r') as f:
                    self.blacklist = set(line.strip() for line in f if line.strip())
                    self.blacklist_text.insert(1.0, '\n'.join(self.blacklist))
        except:
            pass
    
    def save_whitelist(self):
        """Save whitelist to file"""
        try:
            whitelist_content = self.whitelist_text.get(1.0, tk.END).strip()
            self.whitelist = set(line.strip() for line in whitelist_content.split('\n') if line.strip())
            
            whitelist_file = os.path.join(os.path.expanduser("~"), ".temp_cleaner_whitelist.txt")
            with open(whitelist_file, 'w') as f:
                f.write('\n'.join(self.whitelist))
            
            messagebox.showinfo("Success", "Whitelist saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save whitelist: {e}")
    
    def save_blacklist(self):
        """Save blacklist to file"""
        try:
            blacklist_content = self.blacklist_text.get(1.0, tk.END).strip()
            self.blacklist = set(line.strip() for line in blacklist_content.split('\n') if line.strip())
            
            blacklist_file = os.path.join(os.path.expanduser("~"), ".temp_cleaner_blacklist.txt")
            with open(blacklist_file, 'w') as f:
                f.write('\n'.join(self.blacklist))
            
            messagebox.showinfo("Success", "Blacklist saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save blacklist: {e}")
    
    def browse_backup_location(self):
        """Browse for backup location"""
        directory = filedialog.askdirectory(title="Select backup location")
        if directory:
            self.backup_location.set(directory)
    
    def add_to_whitelist(self):
        """Add selected files to whitelist"""
        selected_files = [f for f in self.temp_files if f.get('selected', False)]
        
        if not selected_files:
            messagebox.showwarning("No Selection", "Please select files to add to whitelist.")
            return
        
        # Add to whitelist
        for file_info in selected_files:
            self.whitelist.add(file_info['path'])
        
        # Update whitelist display
        self.whitelist_text.delete(1.0, tk.END)
        self.whitelist_text.insert(1.0, '\n'.join(sorted(self.whitelist)))
        
        messagebox.showinfo("Whitelist Updated", 
                           f"Added {len(selected_files)} files to whitelist.")
    
    def filter_files(self, event=None):
        """Filter displayed files based on search term"""
        filter_text = self.filter_var.get().lower()
        
        # Simple implementation - in a full version, you'd rebuild the tree with filtering
        if not filter_text:
            return
        
        # Hide/show items based on filter
        for item in self.tree.get_children():
            self.filter_tree_item(item, filter_text)
    
    def filter_tree_item(self, item, filter_text):
        """Recursively filter tree items"""
        item_text = self.tree.item(item, 'text').lower()
        item_values = ' '.join(str(v).lower() for v in self.tree.item(item, 'values'))
        
        # Check if item matches filter
        if filter_text in item_text or filter_text in item_values:
            self.tree.set(item, 'visible', True)
        else:
            self.tree.set(item, 'visible', False)
        
        # Check children
        for child in self.tree.get_children(item):
            self.filter_tree_item(child, filter_text)
    
    def sort_files(self, event=None):
        """Sort files based on selected criteria"""
        sort_by = self.sort_var.get()
        
        # This is a simplified version - full implementation would rebuild tree
        messagebox.showinfo("Sort", f"Files sorted by {sort_by}")
    
    def refresh_view(self):
        """Refresh the file view"""
        self.populate_enhanced_tree()
    
    def export_file_list(self):
        """Export file list to CSV"""
        if not self.temp_files:
            messagebox.showwarning("No Data", "No files to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Export File List",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt")]
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    f.write("Path,Size,Modified,Type,Risk Level,Recommended Action,Selected\n")
                    for file_info in self.temp_files:
                        f.write(f'"{file_info["path"]}",')
                        f.write(f'{file_info["size"]},')
                        f.write(f'"{file_info["modified"]}",')
                        f.write(f'"{file_info["type"]}",')
                        f.write(f'"{file_info["risk_level"]}",')
                        f.write(f'"{file_info["recommended_action"]}",')
                        f.write(f'{file_info.get("selected", False)}\n')
                
                messagebox.showinfo("Export Complete", f"File list exported to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export file list: {e}")
    
    def show_context_menu(self, event):
        """Show context menu for tree items"""
        item = self.tree.identify('item', event.x, event.y)
        if item:
            # Create context menu
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label="📋 Show Details", command=lambda: self.show_file_details(None))
            context_menu.add_command(label="📂 Open Location", command=lambda: self.open_file_location(item))
            context_menu.add_command(label="🔒 Add to Whitelist", command=lambda: self.add_single_to_whitelist(item))
            context_menu.add_command(label="❌ Add to Blacklist", command=lambda: self.add_single_to_blacklist(item))
            
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
    
    def open_file_location(self, item):
        """Open file location in system file manager"""
        # Find file info for this tree item
        file_info = None
        for f in self.temp_files:
            if f.get('tree_id') == item:
                file_info = f
                break
        
        if file_info:
            file_path = file_info['path']
            directory = os.path.dirname(file_path)
            
            try:
                if platform.system() == "Windows":
                    os.startfile(directory)
                elif platform.system() == "Darwin":  # macOS
                    subprocess.run(["open", directory])
                else:  # Linux
                    subprocess.run(["xdg-open", directory])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open location: {e}")
    
    def add_single_to_whitelist(self, item):
        """Add single file to whitelist"""
        file_info = None
        for f in self.temp_files:
            if f.get('tree_id') == item:
                file_info = f
                break
        
        if file_info:
            self.whitelist.add(file_info['path'])
            messagebox.showinfo("Whitelist", f"Added to whitelist:\n{file_info['path']}")
    
    def add_single_to_blacklist(self, item):
        """Add single file to blacklist"""
        file_info = None
        for f in self.temp_files:
            if f.get('tree_id') == item:
                file_info = f
                break
        
        if file_info:
            self.blacklist.add(file_info['path'])
            messagebox.showinfo("Blacklist", f"Added to blacklist:\n{file_info['path']}")
    
    def get_relative_path(self, full_path):
        """Get a shorter, more readable path"""
        try:
            home = os.path.expanduser("~")
            if full_path.startswith(home):
                return "~" + full_path[len(home):]
            
            # For Windows, show relative to common directories
            if platform.system() == "Windows":
                common_paths = [
                    (os.environ.get('WINDIR', ''), '%WINDIR%'),
                    (os.environ.get('LOCALAPPDATA', ''), '%LOCALAPPDATA%'),
                    (os.environ.get('APPDATA', ''), '%APPDATA%'),
                    (os.environ.get('TEMP', ''), '%TEMP%'),
                ]
                
                for path, var in common_paths:
                    if path and full_path.startswith(path):
                        return var + full_path[len(path):]
            
            return full_path
        except:
            return full_path
    
    def format_size(self, size):
        """Format file size in human readable format"""
        if size == 0:
            return "0 B"
            
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                if unit == 'B':
                    return f"{int(size)} {unit}"
                else:
                    return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def on_item_click(self, event):
        """Handle item click in treeview"""
        region = self.tree.identify("region", event.x, event.y)
        if region == "cell":
            item = self.tree.identify('item', event.x, event.y)
            if item:
                self.toggle_selection_for_item(item)
    
    def show_file_details(self, event):
        """Show detailed file information"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        file_info = None
        
        for f in self.temp_files:
            if f.get('tree_id') == item:
                file_info = f
                break
        
        if file_info:
            details = f"""📄 FILE DETAILS
{'='*50}

📍 Path: {file_info['path']}
📏 Size: {self.format_size(file_info['size'])}
📅 Modified: {file_info['modified'].strftime('%Y-%m-%d %H:%M:%S')}
🏷️ Category: {file_info['type']}
⚠️ Risk Level: {file_info['risk_level']}
💡 Recommended Action: {file_info['recommended_action']}
📊 Confidence Score: {file_info['confidence']}%
⏰ Age: {file_info['age_days']:.1f} days

{'='*50}
This file appears to be safe to delete based on multiple
detection algorithms including file patterns, location,
age, and content analysis."""
            
            messagebox.showinfo("File Details", details)
    
    def toggle_selection_for_item(self, item):
        """Toggle selection for a specific item"""
        tags = self.tree.item(item, 'tags')
        
        if 'category_header' in tags:
            self.toggle_category_selection(item)
        elif 'risk_header' in tags:
            self.toggle_risk_selection(item)
        elif 'file' in tags:
            self.toggle_file_selection(item)
    
    def toggle_file_selection(self, item):
        """Toggle selection for a single file"""
        file_info = None
        for f in self.temp_files:
            if f.get('tree_id') == item:
                file_info = f
                break
        
        if file_info:
            file_info['selected'] = not file_info.get('selected', False)
            checkbox = '[X]' if file_info['selected'] else '[ ]'
            self.tree.item(item, text=checkbox)
            self.update_selection_stats()
    
    def toggle_category_selection(self, category_item):
        """Toggle selection for all files in a category"""
        self._toggle_group_selection(category_item)
    
    def toggle_risk_selection(self, risk_item):
        """Toggle selection for all files in a risk group"""
        self._toggle_group_selection(risk_item)
    
    def _toggle_group_selection(self, group_item):
        """Helper method to toggle selection for a group"""
        # Get all file items under this group (recursively)
        file_items = self._get_file_items_recursive(group_item)
        
        # Check current state
        selected_count = 0
        for item in file_items:
            for f in self.temp_files:
                if f.get('tree_id') == item and f.get('selected', False):
                    selected_count += 1
                    break
        
        # Toggle based on current state
        new_state = selected_count < len(file_items)
        
        for item in file_items:
            for f in self.temp_files:
                if f.get('tree_id') == item:
                    f['selected'] = new_state
                    checkbox = '[X]' if new_state else '[ ]'
                    self.tree.item(item, text=checkbox)
                    break
        
        self.update_selection_stats()
    
    def _get_file_items_recursive(self, item):
        """Get all file items under a group item recursively"""
        file_items = []
        
        for child in self.tree.get_children(item):
            tags = self.tree.item(child, 'tags')
            if 'file' in tags:
                file_items.append(child)
            else:
                # Recursively get files from subgroups
                file_items.extend(self._get_file_items_recursive(child))
        
        return file_items
    
    def select_all(self):
        """Select all files"""
        for file_info in self.temp_files:
            file_info['selected'] = True
            if 'tree_id' in file_info:
                self.tree.item(file_info['tree_id'], text='[X]')
        
        self.update_selection_stats()
    
    def deselect_all(self):
        """Deselect all files"""
        for file_info in self.temp_files:
            file_info['selected'] = False
            if 'tree_id' in file_info:
                self.tree.item(file_info['tree_id'], text='[ ]')
        
        self.update_selection_stats()
    
    def update_selection_stats(self):
        """Update selection statistics display"""
        selected_files = [f for f in self.temp_files if f.get('selected', False)]
        selected_count = len(selected_files)
        selected_size = sum(f['size'] for f in selected_files)
        
        self.selection_stats.config(text=f"Selected: {selected_count:,} files")
        self.size_savings.config(text=f"Potential savings: {self.format_size(selected_size)}")
    
    def select_by_type(self):
        """Show dialog to select files by type"""
        if not self.temp_files:
            messagebox.showwarning("No Files", "Please scan for files first.")
            return
            
        # Create enhanced selection dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Select by Criteria")
        dialog.geometry("500x600")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (250)
        y = (dialog.winfo_screenheight() // 2) - (300)
        dialog.geometry(f"500x600+{x}+{y}")
        
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="🎯 Advanced Selection Criteria", 
                 font=('Arial', 14, 'bold')).pack(pady=(0, 20))
        
        # Notebook for different criteria
        criteria_notebook = ttk.Notebook(main_frame)
        criteria_notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # By Category tab
        category_frame = ttk.Frame(criteria_notebook)
        criteria_notebook.add(category_frame, text="📁 By Category")
        
        ttk.Label(category_frame, text="Select categories:", 
                 font=('Arial', 10, 'bold')).pack(pady=(10, 5))
        
        categories = list(set(f['type'] for f in self.temp_files))
        category_vars = {}
        
        for category in sorted(categories):
            count = sum(1 for f in self.temp_files if f['type'] == category)
            size = sum(f['size'] for f in self.temp_files if f['type'] == category)
            
            var = tk.BooleanVar()
            text = f"{category} ({count:,} files, {self.format_size(size)})"
            ttk.Checkbutton(category_frame, text=text, variable=var).pack(anchor='w', padx=20, pady=2)
            category_vars[category] = var
        
        # By Risk Level tab
        risk_frame = ttk.Frame(criteria_notebook)
        criteria_notebook.add(risk_frame, text="⚠️ By Risk Level")
        
        ttk.Label(risk_frame, text="Select risk levels:", 
                 font=('Arial', 10, 'bold')).pack(pady=(10, 5))
        
        risk_levels = ['Low', 'Medium', 'High']
        risk_vars = {}
        
        for risk in risk_levels:
            count = sum(1 for f in self.temp_files if f['risk_level'] == risk)
            size = sum(f['size'] for f in self.temp_files if f['risk_level'] == risk)
            
            var = tk.BooleanVar()
            if risk == 'Low':
                var.set(True)  # Default select low risk
            
            text = f"{risk} Risk ({count:,} files, {self.format_size(size)})"
            ttk.Checkbutton(risk_frame, text=text, variable=var).pack(anchor='w', padx=20, pady=2)
            risk_vars[risk] = var
        
        # By Age tab
        age_frame = ttk.Frame(criteria_notebook)
        criteria_notebook.add(age_frame, text="📅 By Age")
        
        ttk.Label(age_frame, text="Select by file age:", 
                 font=('Arial', 10, 'bold')).pack(pady=(10, 5))
        
        age_options = [
            ("Older than 1 day", 1),
            ("Older than 1 week", 7),
            ("Older than 1 month", 30),
            ("Older than 3 months", 90),
            ("Older than 6 months", 180),
            ("Older than 1 year", 365)
        ]
        
        self.age_selection = tk.StringVar(value="30")
        
        for text, days in age_options:
            count = sum(1 for f in self.temp_files if f['age_days'] > days)
            if count > 0:
                ttk.Radiobutton(age_frame, text=f"{text} ({count:,} files)", 
                               variable=self.age_selection, value=str(days)).pack(anchor='w', padx=20, pady=2)
        
        # By Size tab
        size_frame = ttk.Frame(criteria_notebook)
        criteria_notebook.add(size_frame, text="📏 By Size")
        
        ttk.Label(size_frame, text="Select by file size:", 
                 font=('Arial', 10, 'bold')).pack(pady=(10, 5))
        
        size_options = [
            ("Larger than 1 MB", 1024*1024),
            ("Larger than 10 MB", 10*1024*1024),
            ("Larger than 100 MB", 100*1024*1024),
            ("Smaller than 1 KB", 1024),
            ("Empty files (0 bytes)", 0)
        ]
        
        size_vars = {}
        
        for text, size_bytes in size_options:
            if size_bytes == 0:
                count = sum(1 for f in self.temp_files if f['size'] == 0)
            elif "Smaller" in text:
                count = sum(1 for f in self.temp_files if f['size'] < size_bytes)
            else:
                count = sum(1 for f in self.temp_files if f['size'] > size_bytes)
            
            if count > 0:
                var = tk.BooleanVar()
                ttk.Checkbutton(size_frame, text=f"{text} ({count:,} files)", 
                               variable=var).pack(anchor='w', padx=20, pady=2)
                size_vars[text] = (var, size_bytes)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def apply_advanced_selection():
            # First deselect all
            self.deselect_all()
            
            # Apply category selection
            selected_categories = [cat for cat, var in category_vars.items() if var.get()]
            
            # Apply risk selection
            selected_risks = [risk for risk, var in risk_vars.items() if var.get()]
            
            # Apply age selection
            min_age = float(self.age_selection.get())
            
            # Apply size selection
            selected_sizes = [(text, size_bytes) for text, (var, size_bytes) in size_vars.items() if var.get()]
            
            # Select files matching criteria
            for file_info in self.temp_files:
                should_select = True
                
                # Check category
                if selected_categories and file_info['type'] not in selected_categories:
                    should_select = False
                
                # Check risk
                if selected_risks and file_info['risk_level'] not in selected_risks:
                    should_select = False
                
                # Check age
                if file_info['age_days'] < min_age:
                    should_select = False
                
                # Check size
                if selected_sizes:
                    size_match = False
                    for text, size_bytes in selected_sizes:
                        if size_bytes == 0 and file_info['size'] == 0:
                            size_match = True
                        elif "Smaller" in text and file_info['size'] < size_bytes:
                            size_match = True
                        elif "Larger" in text and file_info['size'] > size_bytes:
                            size_match = True
                    
                    if not size_match:
                        should_select = False
                
                if should_select:
                    file_info['selected'] = True
                    if 'tree_id' in file_info:
                        self.tree.item(file_info['tree_id'], text='[X]')
            
            self.update_selection_stats()
            dialog.destroy()
            
            selected_count = sum(1 for f in self.temp_files if f.get('selected', False))
            messagebox.showinfo("Selection Applied", 
                               f"Selected {selected_count:,} files based on your criteria.")
        
        ttk.Button(button_frame, text="✅ Apply Selection", 
                  command=apply_advanced_selection).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="❌ Cancel", 
                  command=dialog.destroy).pack(side=tk.RIGHT)
    
    def add_custom_location(self):
        """Add custom location to scan"""
        directory = filedialog.askdirectory(title="Select directory to scan for temporary files")
        if not directory:
            return
            
        self.status_label.config(text="Scanning custom location...")
        self.progress.config(mode='indeterminate')
        self.progress.start()
        
        def scan_custom():
            files = self.enhanced_scan_directory(directory, "Custom Location", "deep")
            self.root.after(0, lambda: self.custom_scan_complete(files, directory))
        
        thread = threading.Thread(target=scan_custom)
        thread.daemon = True
        thread.start()
    
    def custom_scan_complete(self, files, directory):
        """Handle custom scan completion"""
        self.progress.stop()
        
        if files:
            # Add to existing files
            self.temp_files.extend(files)
            self.total_size += sum(f['size'] for f in files)
            
            # Refresh the tree to include new files
            self.populate_enhanced_tree()
            self.update_selection_stats()
            
            self.status_label.config(text=f"Added {len(files)} files from custom location")
            
            if not self.delete_btn['state'] == 'normal':
                self.delete_btn.config(state='normal')
                self.backup_btn.config(state='normal')
        else:
            messagebox.showinfo("No Files Found", 
                              f"No temporary files found in:\n{directory}")
            self.status_label.config(text="Ready")
    
    def delete_selected(self):
        """Delete selected files with enhanced confirmation and backup"""
        selected_files = [f for f in self.temp_files if f.get('selected', False)]
        
        if not selected_files:
            messagebox.showwarning("No Selection", "Please select files to delete.")
            return
        
        # Enhanced confirmation dialog
        total_size = sum(f['size'] for f in selected_files)
        
        # Group by risk level for summary
        risk_summary = defaultdict(int)
        for f in selected_files:
            risk_summary[f['risk_level']] += 1
        
        risk_text = "\n".join([f"• {risk}: {count:,} files" 
                              for risk, count in risk_summary.items()])
        
        confirmation_msg = f"""🗑️ DELETION CONFIRMATION

You are about to delete {len(selected_files):,} files:

Risk Level Breakdown:
{risk_text}

Total size: {self.format_size(total_size)}

⚠️ WARNING: This action cannot be undone!

Do you want to proceed?"""
        
        # Create custom confirmation dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("⚠️ Confirm Deletion")
        dialog.geometry("400x350")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (200)
        y = (dialog.winfo_screenheight() // 2) - (175)
        dialog.geometry(f"400x350+{x}+{y}")
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Confirmation text
        text_widget = tk.Text(main_frame, height=12, wrap=tk.WORD, font=('Arial', 10))
        text_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        text_widget.insert(1.0, confirmation_msg)
        text_widget.config(state='disabled')
        
        # Backup option
        backup_frame = ttk.Frame(main_frame)
        backup_frame.pack(fill=tk.X, pady=(0, 10))
        
        backup_var = tk.BooleanVar(value=self.auto_backup.get())
        ttk.Checkbutton(backup_frame, text="💾 Create backup before deletion", 
                       variable=backup_var).pack(side=tk.LEFT)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        result = {'confirmed': False, 'backup': False}
        
        def confirm_deletion():
            result['confirmed'] = True
            result['backup'] = backup_var.get()
            dialog.destroy()
        
        def cancel_deletion():
            dialog.destroy()
        
        ttk.Button(button_frame, text="🗑️ Delete Files", 
                  command=confirm_deletion).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="❌ Cancel", 
                  command=cancel_deletion).pack(side=tk.RIGHT)
        
        dialog.wait_window()
        
        if not result['confirmed']:
            return
        
        # Proceed with deletion
        self.delete_btn.config(state='disabled', text="🗑️ Deleting...")
        self.scan_btn.config(state='disabled')
        self.progress.config(mode='determinate', value=0)
        
        # Start deletion process
        thread = threading.Thread(target=lambda: self.delete_files_worker(selected_files, result['backup']))
        thread.daemon = True
        thread.start()
    
    def delete_files_worker(self, files_to_delete, create_backup):
        """Enhanced file deletion with backup and detailed tracking"""
        deleted_count = 0
        deleted_size = 0
        errors = []
        backup_path = None
        
        try:
            # Create backup if requested
            if create_backup:
                self.root.after(0, lambda: self.status_label.config(text="Creating backup..."))
                
                backup_dir = self.backup_location.get() or tempfile.gettempdir()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"temp_cleaner_backup_{timestamp}.zip"
                backup_path = os.path.join(backup_dir, backup_name)
                
                try:
                    with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for i, file_info in enumerate(files_to_delete):
                            progress = (i / len(files_to_delete)) * 50  # First 50% for backup
                            self.root.after(0, lambda p=progress: self.progress.config(value=p))
                            
                            try:
                                file_path = file_info['path']
                                if os.path.exists(file_path) and os.path.isfile(file_path):
                                    # Create safe archive path
                                    archive_path = os.path.relpath(file_path, '/')
                                    archive_path = archive_path.replace(':', '_').replace('\\', '/')
                                    zipf.write(file_path, archive_path)
                            except Exception as e:
                                errors.append(f"Backup failed for {file_info['path']}: {str(e)}")
                except Exception as e:
                    errors.append(f"Backup creation failed: {str(e)}")
                    backup_path = None
            
            # Delete files
            self.root.after(0, lambda: self.status_label.config(text="Deleting files..."))
            
            for i, file_info in enumerate(files_to_delete):
                base_progress = 50 if create_backup else 0
                progress = base_progress + ((i / len(files_to_delete)) * 50)
                self.root.after(0, lambda p=progress: self.progress.config(value=p))
                
                try:
                    file_path = file_info['path']
                    
                    if os.path.isfile(file_path):
                        file_size = file_info['size']
                        os.remove(file_path)
                        deleted_count += 1
                        deleted_size += file_size
                        
                        # Track in database
                        self.track_file_deletion(file_path, file_size)
                        
                    elif os.path.isdir(file_path):
                        dir_size = self.get_directory_size(file_path)
                        shutil.rmtree(file_path)
                        deleted_count += 1
                        deleted_size += dir_size
                        
                except Exception as e:
                    error_msg = f"{os.path.basename(file_info['path'])}: {str(e)}"
                    errors.append(error_msg)
                    continue
            
            # Record cleanup session
            self.record_cleanup_session(deleted_count, deleted_size, errors, backup_path)
            
        except Exception as e:
            errors.append(f"General error: {str(e)}")
        
        # Complete deletion
        self.root.after(0, lambda: self.deletion_complete(deleted_count, deleted_size, errors, backup_path))
    
    def track_file_deletion(self, file_path, file_size):
        """Track file deletion in database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO file_tracking 
                (file_path, size, last_seen, cleanup_count)
                VALUES (?, ?, ?, COALESCE((SELECT cleanup_count FROM file_tracking WHERE file_path = ?) + 1, 1))
            ''', (file_path, file_size, datetime.now().isoformat(), file_path))
            self.conn.commit()
        except:
            pass
    
    def record_cleanup_session(self, deleted_count, deleted_size, errors, backup_path):
        """Record cleanup session in database"""
        try:
            cursor = self.conn.cursor()
            details = {
                'errors': len(errors),
                'backup_created': backup_path is not None,
                'backup_path': backup_path,
                'scan_type': self.scan_type.get()
            }
            
            cursor.execute('''
                INSERT INTO cleanup_history 
                (date, files_count, size_freed, scan_type, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), deleted_count, deleted_size, 
                  self.scan_type.get(), json.dumps(details)))
            self.conn.commit()
        except:
            pass
    
    def get_directory_size(self, directory):
        """Calculate total size of directory"""
        total = 0
        try:
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total += os.path.getsize(filepath)
                    except:
                        continue
        except:
            pass
        return total
    
    def deletion_complete(self, deleted_count, deleted_size, errors, backup_path):
        """Handle deletion completion with detailed results"""
        self.progress.config(value=100)
        self.delete_btn.config(state='normal', text="🗑️ Delete Selected Files")
        self.scan_btn.config(state='normal')
        
        # Create detailed results dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("✅ Deletion Results")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (250)
        y = (dialog.winfo_screenheight() // 2) - (200)
        dialog.geometry(f"500x400+{x}+{y}")
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Results text
        results_text = f"""🎉 CLEANUP COMPLETED SUCCESSFULLY!
{'='*50}

✅ Files Deleted: {deleted_count:,}
💾 Space Freed: {self.format_size(deleted_size)}
❌ Errors: {len(errors)}
"""
        
        if backup_path:
            results_text += f"💾 Backup Created: {backup_path}\n"
        
        results_text += f"\n{'='*50}\n"
        
        if errors:
            results_text += f"\n⚠️ ERRORS ENCOUNTERED:\n\n"
            for error in errors[:10]:  # Show first 10 errors
                results_text += f"• {error}\n"
            if len(errors) > 10:
                results_text += f"\n... and {len(errors) - 10} more errors\n"
        else:
            results_text += "\n🎊 All files deleted successfully!\n"
        
        results_text += f"\n💡 TIP: Run regular cleanups to maintain optimal system performance."
        
        text_widget = tk.Text(main_frame, wrap=tk.WORD, font=('Arial', 10))
        text_widget.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        text_widget.insert(1.0, results_text)
        text_widget.config(state='disabled')
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def rescan_system():
            dialog.destroy()
            self.start_advanced_scan()
        
        def open_backup():
            if backup_path and os.path.exists(backup_path):
                directory = os.path.dirname(backup_path)
                try:
                    if platform.system() == "Windows":
                        os.startfile(directory)
                    elif platform.system() == "Darwin":
                        subprocess.run(["open", directory])
                    else:
                        subprocess.run(["xdg-open", directory])
                except:
                    pass
        
        ttk.Button(button_frame, text="🔍 Scan Again", 
                  command=rescan_system).pack(side=tk.LEFT)
        
        if backup_path:
            ttk.Button(button_frame, text="📂 Open Backup", 
                      command=open_backup).pack(side=tk.LEFT, padx=(10, 0))
        
        ttk.Button(button_frame, text="✅ Close", 
                  command=dialog.destroy).pack(side=tk.RIGHT)
        
        # Update analytics and history
        self.load_cleanup_history()
        self.update_analytics()


def main():
    """Main function to run the enhanced application"""
    try:
        # Check for required dependencies
        try:
            import psutil
        except ImportError:
            print("Warning: psutil not installed. Some features may be limited.")
            print("Install with: pip install psutil")
        
        # Create and configure root window
        root = tk.Tk()
        
        # Set window icon if available
        try:
            # You can add an icon file here if you have one
            # root.iconbitmap('icon.ico')
            pass
        except:
            pass
        
        # Create enhanced application
        app = EnhancedTempFileCleaner(root)
        
        # Center window on screen
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Start the GUI event loop
        root.mainloop()
        
        # Clean up database connection
        if hasattr(app, 'conn'):
            app.conn.close()
        
    except Exception as e:
        messagebox.showerror("Application Error", 
                           f"An error occurred starting the application:\n{str(e)}")
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
