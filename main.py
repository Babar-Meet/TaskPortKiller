#!/usr/bin/env python3
"""
TaskPortKiller - Professional Ports/Processes Management Tool
Author: Giga Potato
Date: 2026-02-16
Version: 1.0.0

A modern Windows desktop application for managing listening ports and processes with ttk styling,
threading, and comprehensive error handling.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil
import threading
import time
import re
import socket
from typing import List, Dict, Any, Optional
import sys
import os


# ==============================
# Configuration Constants
# ==============================
DEFAULT_REFRESH_INTERVAL = 5000  # milliseconds (default)
MIN_REFRESH_INTERVAL = 500  # minimum allowed (500ms)
MAX_REFRESH_INTERVAL = 60000  # maximum allowed (60 seconds)
IGNORE_PROCESSES = {"System", "Registry", "Idle"}
IGNORE_EXECUTABLES = {"svchost.exe"}
IGNORE_PATHS = {
    "C:\\Windows\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
}
SPECIAL_IPS = {"::", "0.0.0.0"}
CRITICAL_PROCESS_NAMES = {"csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}


# ==============================
# Utility Functions
# ==============================
def is_system_process(proc: psutil.Process) -> bool:
    """Determine if a process is a system process to ignore."""
    try:
        name = proc.name()
        if name in CRITICAL_PROCESS_NAMES:
            return True
        if name in IGNORE_EXECUTABLES:
            return True
        if proc.username() == "NT AUTHORITY\\SYSTEM":
            return True
        if proc.exe():
            exe_path = proc.exe().lower()
            for ignore_path in IGNORE_PATHS:
                if exe_path.startswith(ignore_path.lower()):
                    return True
        return False
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return True
    except Exception as e:
        return True


def get_all_processes(show_all: bool = False) -> List[psutil.Process]:
    """Get all processes, with optional system process filtering."""
    processes = []
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                if proc.pid in (0, 140):  # Skip special system processes that can't be interacted with
                    continue
                if not show_all and is_system_process(proc):
                    continue
                if proc.pid == os.getpid():
                    continue
                processes.append(proc)
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except Exception as e:
                print(f"Error processing process {proc.pid}: {e}")
                continue
    except Exception as e:
        print(f"Error getting processes: {e}")
        show_error("Error", f"Failed to retrieve processes: {str(e)}")
    return processes


def get_listening_ports(show_all: bool = False) -> List[Dict[str, Any]]:
    """Get all active listening ports with associated process information, with optional system process filtering."""
    listening_ports = []
    try:
        connections = psutil.net_connections(kind="inet")
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                entry = {
                    "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "local_ip": conn.laddr.ip if conn.laddr else "Unknown",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "pid": conn.pid,
                    "process": "Unknown"
                }
                if conn.pid and conn.pid != -1:
                    try:
                        proc = psutil.Process(conn.pid)
                        entry["process"] = sanitize_string(proc.name())
                        # Filter out system processes if show_all is False
                        if not show_all and is_system_process(proc):
                            continue
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        entry["process"] = "Access Denied"
                listening_ports.append(entry)
    except Exception as e:
        print(f"Error getting listening ports: {e}")
        show_error("Error", f"Failed to retrieve listening ports: {str(e)}")
    return listening_ports


def sanitize_string(text: str) -> str:
    """Safely handle text for UI display."""
    if text is None:
        return ""
    try:
        return str(text).strip()
    except:
        return ""


def show_error(title: str, message: str):
    """Show error message."""
    try:
        messagebox.showerror(title, message)
    except Exception as e:
        print(f"Error showing error message: {e}")


def show_warning(title: str, message: str):
    """Show warning message."""
    try:
        messagebox.showwarning(title, message)
    except Exception as e:
        print(f"Error showing warning message: {e}")


def ask_confirmation(title: str, message: str) -> bool:
    """Ask for user confirmation."""
    try:
        return messagebox.askyesno(title, message)
    except Exception as e:
        print(f"Error showing confirmation: {e}")
        return False


# ==============================
# Port Management Logic
# ==============================
def kill_port_process(port_info: Dict[str, Any]) -> bool:
    """Kill the process using the specified port."""
    if not port_info.get("pid") or port_info["pid"] == -1:
        return False
    try:
        proc = psutil.Process(port_info["pid"])
        if proc.pid == os.getpid():
            show_warning("Warning", "Cannot kill this application!")
            return False
        if is_system_process(proc):
            show_warning("Warning", "Cannot kill system processes!")
            return False
        confirm = ask_confirmation(
            "Kill Process",
            f"Kill process '{port_info['process']}' (PID: {port_info['pid']}) on port {port_info['local_port']}?"
        )
        if not confirm:
            return False
        proc.terminate()
        return True
    except psutil.NoSuchProcess:
        show_error("Error", "Process not found!")
        return False
    except psutil.AccessDenied:
        show_error("Error", "Access denied! Cannot terminate this process.")
        return False
    except Exception as e:
        show_error("Error", f"Failed to kill process: {str(e)}")
        return False


# ==============================
# Process Management Logic
# ==============================
def get_process_info(proc: psutil.Process) -> Dict[str, Any]:
    """Extract detailed information from a process."""
    # Handle special system processes (PID 0 and PID 140) that can't be interacted with
    if proc.pid == 0:
        return {
            "pid": 0,
            "name": "System Idle Process",
            "exe": "",
            "username": "NT AUTHORITY\\SYSTEM",
            "status": "Unknown",
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "threads": 0,
            "create_time": 0,
            "command_line": ""
        }
    if proc.pid == 140:
        return {
            "pid": 140,
            "name": "System",
            "exe": "",
            "username": "NT AUTHORITY\\SYSTEM",
            "status": "Unknown",
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "threads": 0,
            "create_time": 0,
            "command_line": ""
        }
    
    info = {
        "pid": proc.pid,
        "name": "",
        "exe": "",
        "username": "",
        "status": "Unknown",
        "cpu_usage": 0.0,
        "memory_usage": 0.0,
        "threads": 0,
        "create_time": 0,
        "command_line": ""
    }
    try:
        info["name"] = sanitize_string(proc.name())
        info["exe"] = sanitize_string(proc.exe() if hasattr(proc, "exe") else "")
        info["username"] = sanitize_string(proc.username())
        info["status"] = sanitize_string(proc.status())
        info["cpu_usage"] = round(proc.cpu_percent(), 2)
        info["memory_usage"] = round(proc.memory_info().rss / (1024 * 1024), 2)  # MB
        info["threads"] = proc.num_threads()
        info["create_time"] = proc.create_time()
        cmdline = proc.cmdline()
        info["command_line"] = " ".join(sanitize_string(arg) for arg in cmdline) if cmdline else ""
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        pass
    except Exception as e:
        print(f"Error getting process info for PID {proc.pid}: {e}")
    return info


def kill_process(proc: psutil.Process) -> bool:
    """Kill a specific process with safety checks."""
    if proc.pid == os.getpid():
        show_warning("Warning", "Cannot kill this application!")
        return False
    if is_system_process(proc):
        show_warning("Warning", "Cannot kill system processes!")
        return False
    try:
        confirm = ask_confirmation(
            "Kill Process",
            f"Kill process '{proc.name()}' (PID: {proc.pid})? This cannot be undone."
        )
        if not confirm:
            return False
        proc.terminate()
        return True
    except psutil.NoSuchProcess:
        show_error("Error", "Process not found!")
        return False
    except psutil.AccessDenied:
        show_error("Error", "Access denied! Cannot terminate this process.")
        return False
    except Exception as e:
        show_error("Error", f"Failed to kill process: {str(e)}")
        return False


# ==============================
# Quick Kill Logic
# ==============================
def kill_processes_by_ports(ports: List[int], confirm_individual: bool = True) -> Dict[str, List[str]]:
    """Kill processes by listening port numbers with safety checks."""
    results = {"success": [], "failed": [], "skipped": []}
    try:
        connections = psutil.net_connections(kind="inet")
        target_connections = []
        
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port in ports and conn.pid and conn.pid != -1:
                target_connections.append(conn)
        
        # Deduplicate by PID to avoid killing the same process multiple times
        unique_pids = set()
        unique_connections = []
        for conn in target_connections:
            if conn.pid not in unique_pids:
                unique_pids.add(conn.pid)
                unique_connections.append(conn)
        
        for conn in unique_connections:
            try:
                # Re-validate process exists just before killing
                proc = psutil.Process(conn.pid)
                port = conn.laddr.port
                
                if proc.pid == os.getpid():
                    results["skipped"].append(f"Port {port}: Cannot kill this application")
                    continue
                if is_system_process(proc):
                    results["skipped"].append(f"Port {port}: Cannot kill system process '{proc.name()}'")
                    continue
                
                if confirm_individual:
                    confirm = ask_confirmation(
                        "Kill Process",
                        f"Kill process '{proc.name()}' (PID: {proc.pid}) on port {port}?"
                    )
                    if not confirm:
                        results["skipped"].append(f"Port {port}: User cancelled")
                        continue
                
                proc.terminate()
                results["success"].append(f"Port {port}: '{proc.name()}' (PID: {proc.pid}) killed")
                
            except psutil.NoSuchProcess:
                results["failed"].append(f"Port {conn.laddr.port}: Process not found (may have terminated already)")
            except psutil.AccessDenied:
                results["failed"].append(f"Port {conn.laddr.port}: Access denied")
            except Exception as e:
                results["failed"].append(f"Port {conn.laddr.port}: {str(e)}")
    
    except Exception as e:
        results["failed"].append(f"Error: {str(e)}")
    
    return results


def kill_processes_by_names(process_names: List[str], confirm_individual: bool = True) -> Dict[str, List[str]]:
    """Kill processes by name with safety checks."""
    results = {"success": [], "failed": [], "skipped": []}
    try:
        all_processes = get_all_processes()
        
        # Filter processes by name
        target_processes = []
        for proc in all_processes:
            try:
                proc_name = proc.name().lower()
                for target_name in process_names:
                    target_name = target_name.lower()
                    if target_name in proc_name or proc_name in target_name:
                        target_processes.append(proc)
                        break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        
        # Process each target
        for proc in target_processes:
            try:
                # Re-validate process exists just before killing
                proc = psutil.Process(proc.pid)
                
                if proc.pid == os.getpid():
                    results["skipped"].append(f"Process '{proc.name()}': Cannot kill this application")
                    continue
                if is_system_process(proc):
                    results["skipped"].append(f"Process '{proc.name()}': Cannot kill system process")
                    continue
                
                if confirm_individual:
                    confirm = ask_confirmation(
                        "Kill Process",
                        f"Kill process '{proc.name()}' (PID: {proc.pid})?"
                    )
                    if not confirm:
                        results["skipped"].append(f"Process '{proc.name()}' (PID: {proc.pid}): User cancelled")
                        continue
                
                proc.terminate()
                results["success"].append(f"Process '{proc.name()}' (PID: {proc.pid}) killed")
                
            except psutil.NoSuchProcess:
                results["failed"].append(f"Process (PID: {proc.pid}): Process not found (may have terminated already)")
            except psutil.AccessDenied:
                results["failed"].append(f"Process '{proc.name()}' (PID: {proc.pid}): Access denied")
            except Exception as e:
                results["failed"].append(f"Process '{proc.name()}' (PID: {proc.pid}): {str(e)}")
    
    except Exception as e:
        results["failed"].append(f"Error: {str(e)}")
    
    return results


def validate_ports(port_str: str) -> List[int]:
    """Validate and parse port input string."""
    ports = []
    if not port_str.strip():
        return ports
    
    # Split by whitespace
    port_tokens = port_str.strip().split()
    for token in port_tokens:
        token = token.strip()
        if token:
            try:
                port = int(token)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                continue
    
    return list(set(ports))  # Remove duplicates


def validate_process_names(name_str: str) -> List[str]:
    """Validate and parse process name input string."""
    names = []
    if not name_str.strip():
        return names
    
    # Split by whitespace
    name_tokens = name_str.strip().split()
    for token in name_tokens:
        token = token.strip()
        if token and len(token) >= 2:  # Require at least 2 characters
            names.append(token)
    
    return list(set(names))  # Remove duplicates


def format_results(results: Dict[str, List[str]]) -> str:
    """Format kill operation results for display."""
    parts = []
    if results["success"]:
        parts.append("✅ Successfully killed:")
        for item in results["success"]:
            parts.append(f"   - {item}")
    if results["failed"]:
        parts.append("❌ Failed to kill:")
        for item in results["failed"]:
            parts.append(f"   - {item}")
    if results["skipped"]:
        parts.append("⚠️  Skipped:")
        for item in results["skipped"]:
            parts.append(f"   - {item}")
    if not parts:
        return "No processes were targeted."
    return "\n".join(parts)


# ==============================
# UI Components
# ==============================
class QuickKillTab:
    """Quick Kill tab for fast process termination by port or name."""
    
    def __init__(self, parent):
        self.parent = parent
        self.container = ttk.Frame(parent)
        # Get colors from main application
        app = parent.winfo_toplevel()
        self.colors = app.colors
        self.setup_ui()
    
    def setup_ui(self):
        # Main content frame with padding
        main_frame = ttk.Frame(self.container, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Port Input Section
        port_frame = ttk.LabelFrame(main_frame, text="Kill by Port", padding="15")
        port_frame.pack(fill=tk.X, expand=False, pady=(0, 20))
        
        ttk.Label(port_frame, text="Port(s) (space-separated):").pack(side=tk.LEFT, padx=(0, 10))
        self.port_var = tk.StringVar()
        port_entry = ttk.Entry(port_frame, textvariable=self.port_var, font=("Arial", 10))
        port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        port_entry.bind("<KeyRelease>", lambda e: self.update_preview())
        
        # Process Name Input Section
        process_frame = ttk.LabelFrame(main_frame, text="Kill by Process Name", padding="15")
        process_frame.pack(fill=tk.X, expand=False, pady=(0, 20))
        
        ttk.Label(process_frame, text="Process Name(s) (space-separated):").pack(side=tk.LEFT, padx=(0, 10))
        self.process_var = tk.StringVar()
        process_entry = ttk.Entry(process_frame, textvariable=self.process_var, font=("Arial", 10))
        process_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        process_entry.bind("<KeyRelease>", lambda e: self.update_preview())
        
        # Action Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, expand=False, pady=(0, 20))
        
        self.kill_one_btn = ttk.Button(
            button_frame,
            text="Kill One by One",
            command=lambda: self.kill_processes(confirm_individual=True),
            state=tk.DISABLED
        )
        self.kill_one_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.kill_all_btn = ttk.Button(
            button_frame,
            text="Kill All Now",
            command=lambda: self.kill_processes(confirm_individual=False),
            state=tk.DISABLED
        )
        self.kill_all_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_btn = ttk.Button(
            button_frame,
            text="Clear Inputs",
            command=self.clear_inputs
        )
        self.clear_btn.pack(side=tk.LEFT)
        
        # Preview Section
        preview_frame = ttk.LabelFrame(main_frame, text="Preview", padding="15")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        self.preview_text = scrolledtext.ScrolledText(
            preview_frame,
            height=6,
            font=("Arial", 9),
            state=tk.DISABLED
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        
        # Results Section
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="15")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=6,
            font=("Arial", 9),
            state=tk.DISABLED
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
    
    def update_preview(self):
        """Update the preview of processes that will be killed."""
        ports = validate_ports(self.port_var.get())
        process_names = validate_process_names(self.process_var.get())
        
        preview = []
        
        if ports:
            preview.append("=== Ports to kill ===")
            for port in ports:
                preview.append(f"taskkill /PID <pid>  # Kill process on port {port}")
        
        if process_names:
            if ports:  # Add separator if both ports and processes are specified
                preview.append("")
            preview.append("=== Process names to kill ===")
            for name in process_names:
                preview.append(f"taskkill /IM {name}*  # Kill processes matching '{name}'")
        
        # Check if any valid targets
        if ports or process_names:
            self.kill_one_btn.config(state=tk.NORMAL)
            self.kill_all_btn.config(state=tk.NORMAL)
        else:
            self.kill_one_btn.config(state=tk.DISABLED)
            self.kill_all_btn.config(state=tk.DISABLED)
        
        # Display preview
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        if preview:
            self.preview_text.insert(tk.END, "\n".join(preview))
        self.preview_text.config(state=tk.DISABLED)
    
    def kill_processes(self, confirm_individual: bool = True):
        """Execute the kill operation in a separate thread."""
        self.kill_one_btn.config(state=tk.DISABLED)
        self.kill_all_btn.config(state=tk.DISABLED)
        self.clear_btn.config(state=tk.DISABLED)
        
        threading.Thread(target=self.kill_thread, args=(confirm_individual,), daemon=True).start()
    
    def kill_thread(self, confirm_individual: bool = True):
        """Background thread for killing processes."""
        try:
            ports = validate_ports(self.port_var.get())
            process_names = validate_process_names(self.process_var.get())
            
            results = {"success": [], "failed": [], "skipped": []}
            
            if ports:
                port_results = kill_processes_by_ports(ports, confirm_individual)
                results["success"].extend(port_results["success"])
                results["failed"].extend(port_results["failed"])
                results["skipped"].extend(port_results["skipped"])
            
            if process_names:
                name_results = kill_processes_by_names(process_names, confirm_individual)
                results["success"].extend(name_results["success"])
                results["failed"].extend(name_results["failed"])
                results["skipped"].extend(name_results["skipped"])
            
            self.parent.after(0, self.display_results, results)
            
        except Exception as e:
            self.parent.after(0, self.display_results, {"failed": [f"Error: {str(e)}"], "success": [], "skipped": []})
        finally:
            self.parent.after(0, self.enable_buttons)
    
    def display_results(self, results):
        """Display the kill operation results."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, format_results(results))
        self.results_text.config(state=tk.DISABLED)
    
    def enable_buttons(self):
        """Enable the buttons after operation completes."""
        self.update_preview()
        self.clear_btn.config(state=tk.NORMAL)
    


    def clear_inputs(self):
        """Clear all input fields and results."""
        self.port_var.set("")
        self.process_var.set("")
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete("1.0", tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.config(state=tk.DISABLED)
        self.kill_one_btn.config(state=tk.DISABLED)
        self.kill_all_btn.config(state=tk.DISABLED)


class PortsTab:
    """Ports tab for managing listening ports."""

    def __init__(self, parent):
        self.parent = parent
        self.container = ttk.Frame(parent)
        self.refresh_timer = None
        self.refresh_interval = DEFAULT_REFRESH_INTERVAL  # Dynamic interval
        self.setup_ui()

    def setup_ui(self):
        # Search and Control Frame
        control_frame = ttk.Frame(self.container, padding="15")
        control_frame.pack(fill=tk.X, expand=False)

        # Auto Refresh Checkbox with dynamic interval text
        self.auto_refresh_var = tk.BooleanVar(value=True)
        self.auto_refresh_check = ttk.Checkbutton(
            control_frame,
            text=f"Auto Refresh ({self.refresh_interval} ms)",
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh
        )
        self.auto_refresh_check.pack(side=tk.LEFT, padx=(0, 10))

        # Refresh Interval Spinbox
        ttk.Label(control_frame, text="Interval (ms):").pack(side=tk.LEFT, padx=(0, 5))
        self.refresh_interval_var = tk.StringVar(value=str(self.refresh_interval))
        self.refresh_interval_spinbox = ttk.Spinbox(
            control_frame,
            from_=MIN_REFRESH_INTERVAL,
            to=MAX_REFRESH_INTERVAL,
            increment=500,
            textvariable=self.refresh_interval_var,
            width=8,
            command=self.on_refresh_interval_change
        )
        self.refresh_interval_spinbox.pack(side=tk.LEFT, padx=(0, 20))
        # Validate input
        self.refresh_interval_spinbox.bind("<KeyRelease>", self.on_refresh_interval_change)
        self.refresh_interval_spinbox.bind("<FocusOut>", self.on_refresh_interval_change)

        # Refresh Button
        refresh_btn = ttk.Button(
            control_frame,
            text="Refresh",
            command=self.refresh_ports
        )
        refresh_btn.pack(side=tk.RIGHT)

        # Kill Button
        self.kill_btn = ttk.Button(
            control_frame,
            text="Kill Process",
            command=self.kill_selected,
            state=tk.DISABLED
        )
        self.kill_btn.pack(side=tk.RIGHT, padx=(0, 10))

        # Search Frame
        search_frame = ttk.Frame(self.container, padding="0 0 15 15")
        search_frame.pack(fill=tk.X, expand=False)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 10))
        search_entry.bind("<KeyRelease>", lambda e: self.refresh_ports())

        # Port List Table with scrollable frame
        tree_frame = ttk.Frame(self.container)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=0)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("Protocol", "Local IP", "Local Port", "PID", "Process"),
            show="headings",
            selectmode=tk.BROWSE
        )

        # Setup column headings with sorting functionality
        self.sort_column = None
        self.sort_direction = "asc"
        
        self.tree.heading("Protocol", text="Protocol ↑↓", command=lambda: self.sort_by_column("Protocol"))
        self.tree.heading("Local IP", text="Local IP ↑↓", command=lambda: self.sort_by_column("Local IP"))
        self.tree.heading("Local Port", text="Local Port ↑↓", command=lambda: self.sort_by_column("Local Port"))
        self.tree.heading("PID", text="PID ↑↓", command=lambda: self.sort_by_column("PID"))
        self.tree.heading("Process", text="Process ↑↓", command=lambda: self.sort_by_column("Process"))

        self.tree.column("Protocol", width=80)
        self.tree.column("Local IP", width=150)
        self.tree.column("Local Port", width=100)
        self.tree.column("PID", width=100)
        self.tree.column("Process", width=400)

        # Vertical scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        # Horizontal scrollbar
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=hsb.set)

        # Grid layout for treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)

        # Configure grid weights to make treeview expand
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.update_kill_button)

        # Refresh Indicator
        self.refresh_ind = ttk.Label(self.container, text="", font=("Arial", 10, "italic"))
        self.refresh_ind.pack(fill=tk.X, expand=False, padx=15, pady=10)

        # Start auto-refresh
        self.toggle_auto_refresh()

    def sort_by_column(self, col):
        """Sort the treeview by column with visual indicators."""
        # Determine sort direction
        if col == self.sort_column:
            self.sort_direction = "desc" if self.sort_direction == "asc" else "asc"
        else:
            self.sort_column = col
            self.sort_direction = "asc"
        
        # Get all items and values
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children()]
        
        # Sort items based on column type
        try:
            # Try numeric sort
            items.sort(key=lambda x: int(x[0]), reverse=(self.sort_direction == "desc"))
        except ValueError:
            try:
                # Try float sort
                items.sort(key=lambda x: float(x[0]), reverse=(self.sort_direction == "desc"))
            except ValueError:
                # Fallback to string sort
                items.sort(key=lambda x: x[0].lower(), reverse=(self.sort_direction == "desc"))
        
        # Reorder items in the treeview
        for index, (_, item) in enumerate(items):
            self.tree.move(item, "", index)
        
        # Update column headings to show sort indicators
        for column in self.tree["columns"]:
            current_text = column
            if column == self.sort_column:
                current_text += " ↑" if self.sort_direction == "asc" else " ↓"
            else:
                current_text += " ↑↓"
            self.tree.heading(column, text=current_text)
    
    def update_kill_button(self, event=None):
        """Update kill button state based on selected item."""
        selection = self.tree.selection()
        if selection:
            self.kill_btn.config(state=tk.NORMAL)
        else:
            self.kill_btn.config(state=tk.DISABLED)

    def kill_selected(self):
        """Kill the process using the selected port."""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        item = self.tree.item(selected_item)
        port_info = item["values"]
        if port_info and len(port_info) >= 5:
            port_dict = {
                "protocol": port_info[0],
                "local_ip": port_info[1],
                "local_port": int(port_info[2]) if port_info[2] else None,
                "pid": int(port_info[3]) if port_info[3] else None,
                "process": port_info[4]
            }
            success = kill_port_process(port_dict)
            if success:
                self.refresh_ports()

    def refresh_ports(self):
        """Refresh the ports display in a separate thread."""
        threading.Thread(target=self.refresh_thread, daemon=True).start()

    def refresh_thread(self):
        """Background thread for refreshing ports."""
        try:
            self.refresh_ind.config(text="Refreshing...")
            # Get the show_all state from the main application
            app = self.container.winfo_toplevel()
            show_all = app.show_all_processes_var.get()
            ports = get_listening_ports(show_all)

            search_text = self.search_var.get().lower()
            filtered_ports = []
            for port in ports:
                matches = (
                    search_text in port["protocol"].lower() or
                    search_text in port["local_ip"].lower() or
                    search_text in str(port["local_port"]) or
                    search_text in str(port["pid"]) or
                    search_text in port["process"].lower()
                )
                if matches:
                    filtered_ports.append(port)

            self.parent.after(0, self.update_tree, filtered_ports)
        except Exception as e:
            print(f"Refresh error: {e}")
            show_error("Refresh Error", str(e))
        finally:
            self.refresh_ind.config(text=f"Last update: {time.strftime('%H:%M:%S')}")

    def update_tree(self, ports: List[Dict[str, Any]]):
        """Update the tree with new port data and preserve sorting."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        for port in ports:
            self.tree.insert(
                "",
                tk.END,
                values=(
                    port["protocol"],
                    port["local_ip"],
                    port["local_port"],
                    port["pid"] or "",
                    port["process"]
                )
            )
        
        # If there was a previous sort, reapply it
        if self.sort_column:
            self.sort_by_column(self.sort_column)
        
        self.update_kill_button()

    def on_refresh_interval_change(self, event=None):
        """Handle refresh interval change from spinbox."""
        try:
            value = int(self.refresh_interval_var.get())
            # Validate value
            if MIN_REFRESH_INTERVAL <= value <= MAX_REFRESH_INTERVAL:
                self.refresh_interval = value
            else:
                # Clamp to valid range
                if value < MIN_REFRESH_INTERVAL:
                    self.refresh_interval = MIN_REFRESH_INTERVAL
                else:
                    self.refresh_interval = MAX_REFRESH_INTERVAL
                self.refresh_interval_var.set(str(self.refresh_interval))
        except ValueError:
            # Invalid input, reset to previous valid value
            self.refresh_interval_var.set(str(self.refresh_interval))
        
        # Update checkbutton text
        self.auto_refresh_check.config(text=f"Auto Refresh ({self.refresh_interval} ms)")
        
        # If auto refresh is ON, restart timer with new interval
        if self.auto_refresh_var.get():
            self.toggle_auto_refresh()

    def toggle_auto_refresh(self):
        """Toggle auto refresh functionality."""
        if hasattr(self, 'refresh_timer') and self.refresh_timer:
            self.parent.after_cancel(self.refresh_timer)
            self.refresh_timer = None
        if self.auto_refresh_var.get():
            self.refresh_timer = self.parent.after(self.refresh_interval, self.auto_refresh)

    def auto_refresh(self):
        """Automatic refresh callback."""
        if self.auto_refresh_var.get():
            self.refresh_ports()
            self.refresh_timer = self.parent.after(self.refresh_interval, self.auto_refresh)


class ProcessesTab:
    """Processes tab for managing running processes."""

    def __init__(self, parent):
        self.parent = parent
        self.container = ttk.Frame(parent)
        self.refresh_timer = None
        self.refresh_interval = DEFAULT_REFRESH_INTERVAL  # Dynamic interval
        self.setup_ui()

    def setup_ui(self):
        # Search and Control Frame
        control_frame = ttk.Frame(self.container, padding="15")
        control_frame.pack(fill=tk.X, expand=False)

        # Auto Refresh Checkbox with dynamic interval text
        self.auto_refresh_var = tk.BooleanVar(value=True)
        self.auto_refresh_check = ttk.Checkbutton(
            control_frame,
            text=f"Auto Refresh ({self.refresh_interval} ms)",
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh
        )
        self.auto_refresh_check.pack(side=tk.LEFT, padx=(0, 10))

        # Refresh Interval Spinbox
        ttk.Label(control_frame, text="Interval (ms):").pack(side=tk.LEFT, padx=(0, 5))
        self.refresh_interval_var = tk.StringVar(value=str(self.refresh_interval))
        self.refresh_interval_spinbox = ttk.Spinbox(
            control_frame,
            from_=MIN_REFRESH_INTERVAL,
            to=MAX_REFRESH_INTERVAL,
            increment=500,
            textvariable=self.refresh_interval_var,
            width=8,
            command=self.on_refresh_interval_change
        )
        self.refresh_interval_spinbox.pack(side=tk.LEFT, padx=(0, 20))
        # Validate input
        self.refresh_interval_spinbox.bind("<KeyRelease>", self.on_refresh_interval_change)
        self.refresh_interval_spinbox.bind("<FocusOut>", self.on_refresh_interval_change)

        # Refresh Button
        refresh_btn = ttk.Button(
            control_frame,
            text="Refresh",
            command=self.refresh_processes
        )
        refresh_btn.pack(side=tk.RIGHT)

        # Kill Button
        self.kill_btn = ttk.Button(
            control_frame,
            text="Kill Process",
            command=self.kill_selected,
            state=tk.DISABLED
        )
        self.kill_btn.pack(side=tk.RIGHT, padx=(0, 10))

        # Search Frame
        search_frame = ttk.Frame(self.container, padding="0 0 15 15")
        search_frame.pack(fill=tk.X, expand=False)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 10))
        search_entry.bind("<KeyRelease>", lambda e: self.refresh_processes())

        # Process List Table with scrollable frame
        tree_frame = ttk.Frame(self.container)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=0)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=(
                "PID", "Name", "CPU", "Memory", "Threads", "Status",
                "User", "Command Line"
            ),
            show="headings",
            selectmode=tk.BROWSE
        )

        # Setup column headings with sorting functionality
        self.sort_column = None
        self.sort_direction = "asc"
        
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col + " ↑↓", command=lambda c=col: self.sort_by_column(c))

        self.tree.column("PID", width=80, anchor=tk.CENTER)
        self.tree.column("Name", width=150)
        self.tree.column("CPU", width=80, anchor=tk.CENTER)
        self.tree.column("Memory", width=100, anchor=tk.CENTER)
        self.tree.column("Threads", width=80, anchor=tk.CENTER)
        self.tree.column("Status", width=100, anchor=tk.CENTER)
        self.tree.column("User", width=120)
        self.tree.column("Command Line", width=400)

        # Vertical scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        # Horizontal scrollbar
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=hsb.set)

        # Grid layout for treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        vsb.grid(row=0, column=1, sticky=tk.NS)
        hsb.grid(row=1, column=0, sticky=tk.EW)

        # Configure grid weights to make treeview expand
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.update_kill_button)

        # Refresh Indicator
        self.refresh_ind = ttk.Label(self.container, text="", font=("Arial", 10, "italic"))
        self.refresh_ind.pack(fill=tk.X, expand=False, padx=15, pady=10)

        # Start auto-refresh
        self.toggle_auto_refresh()

    def update_kill_button(self, event=None):
        """Update kill button state based on selected item."""
        selection = self.tree.selection()
        if selection:
            self.kill_btn.config(state=tk.NORMAL)
        else:
            self.kill_btn.config(state=tk.DISABLED)

    def sort_by_column(self, col):
        """Sort the treeview by column with visual indicators."""
        # Determine sort direction
        if col == self.sort_column:
            self.sort_direction = "desc" if self.sort_direction == "asc" else "asc"
        else:
            self.sort_column = col
            self.sort_direction = "asc"
        
        # Get all items and values
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children()]
        
        # Sort items based on column type and handle units (like % or MB)
        def get_sortable_value(value):
            # Remove units for numeric comparison
            value = value.strip()
            if value.endswith("%"):
                try:
                    return float(value[:-1])
                except:
                    pass
            if value.endswith(" MB"):
                try:
                    return float(value[:-3])
                except:
                    pass
            return value
        
        # Sort items
        try:
            # Try numeric sort
            items.sort(key=lambda x: int(get_sortable_value(x[0])), reverse=(self.sort_direction == "desc"))
        except ValueError:
            try:
                # Try float sort
                items.sort(key=lambda x: float(get_sortable_value(x[0])), reverse=(self.sort_direction == "desc"))
            except ValueError:
                # Fallback to string sort
                items.sort(key=lambda x: str(get_sortable_value(x[0])).lower(), reverse=(self.sort_direction == "desc"))
        
        # Reorder items in the treeview
        for index, (_, item) in enumerate(items):
            self.tree.move(item, "", index)
        
        # Update column headings to show sort indicators
        for column in self.tree["columns"]:
            current_text = column
            if column == self.sort_column:
                current_text += " ↑" if self.sort_direction == "asc" else " ↓"
            else:
                current_text += " ↑↓"
            self.tree.heading(column, text=current_text)

    def kill_selected(self):
        """Kill the selected process."""
        selected_item = self.tree.selection()
        if not selected_item:
            return
        item = self.tree.item(selected_item)
        pid = int(item["values"][0])
        try:
            proc = psutil.Process(pid)
            success = kill_process(proc)
            if success:
                self.refresh_processes()
        except psutil.NoSuchProcess:
            show_error("Error", "Process not found!")
        except Exception as e:
            show_error("Error", str(e))

    def refresh_processes(self):
        """Refresh the processes display in a separate thread."""
        threading.Thread(target=self.refresh_thread, daemon=True).start()

    def refresh_thread(self):
        """Background thread for refreshing processes."""
        try:
            self.refresh_ind.config(text="Refreshing...")
            # Get the show_all state from the main application
            app = self.container.winfo_toplevel()
            show_all = app.show_all_processes_var.get()
            processes = get_all_processes(show_all)
            process_infos = []
            for proc in processes:
                try:
                    info = get_process_info(proc)
                    process_infos.append(info)
                except Exception as e:
                    print(f"Error processing PID {proc.pid}: {e}")
                    continue

            search_text = self.search_var.get().lower()
            filtered_infos = []
            for info in process_infos:
                try:
                    matches = (
                        search_text in str(info["pid"]) or
                        search_text in info["name"].lower() or
                        search_text in info["username"].lower() or
                        search_text in info["status"].lower() or
                        search_text in info["command_line"].lower()
                    )
                    if matches:
                        filtered_infos.append(info)
                except Exception as e:
                    print(f"Error filtering process info: {e}")
                    continue

            self.parent.after(0, self.update_tree, filtered_infos)
        except Exception as e:
            print(f"Refresh error: {e}")
            show_error("Refresh Error", str(e))
        finally:
            self.refresh_ind.config(text=f"Last update: {time.strftime('%H:%M:%S')}")

    def update_tree(self, process_infos: List[Dict[str, Any]]):
        """Update the tree with new process data and preserve sorting."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        for info in process_infos:
            self.tree.insert(
                "",
                tk.END,
                values=(
                    info["pid"],
                    info["name"],
                    f"{info['cpu_usage']}%",
                    f"{info['memory_usage']:.1f} MB",
                    info["threads"],
                    info["status"],
                    info["username"],
                    info["command_line"]
                )
            )
        
        # If there was a previous sort, reapply it
        if self.sort_column:
            self.sort_by_column(self.sort_column)
        
        self.update_kill_button()

    def on_refresh_interval_change(self, event=None):
        """Handle refresh interval change from spinbox."""
        try:
            value = int(self.refresh_interval_var.get())
            # Validate value
            if MIN_REFRESH_INTERVAL <= value <= MAX_REFRESH_INTERVAL:
                self.refresh_interval = value
            else:
                # Clamp to valid range
                if value < MIN_REFRESH_INTERVAL:
                    self.refresh_interval = MIN_REFRESH_INTERVAL
                else:
                    self.refresh_interval = MAX_REFRESH_INTERVAL
                self.refresh_interval_var.set(str(self.refresh_interval))
        except ValueError:
            # Invalid input, reset to previous valid value
            self.refresh_interval_var.set(str(self.refresh_interval))
        
        # Update checkbutton text
        self.auto_refresh_check.config(text=f"Auto Refresh ({self.refresh_interval} ms)")
        
        # If auto refresh is ON, restart timer with new interval
        if self.auto_refresh_var.get():
            self.toggle_auto_refresh()

    def toggle_auto_refresh(self):
        """Toggle auto refresh functionality."""
        if hasattr(self, 'refresh_timer') and self.refresh_timer:
            self.parent.after_cancel(self.refresh_timer)
            self.refresh_timer = None
        if self.auto_refresh_var.get():
            self.refresh_timer = self.parent.after(self.refresh_interval, self.auto_refresh)

    def auto_refresh(self):
        """Automatic refresh callback."""
        if self.auto_refresh_var.get():
            self.refresh_processes()
            self.refresh_timer = self.parent.after(self.refresh_interval, self.auto_refresh)


class MainApplication(tk.Tk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title("TaskPortKiller v1.0.0 - Professional Ports/Processes Management Tool")
        self.geometry("1200x700")
        self.minsize(1000, 500)
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.setup_styling()
        self.setup_ui()
        
        # Fix for multi-desktop behavior (Windows only)
        self.set_window_desktop_affinity()
    
    def set_window_desktop_affinity(self):
        """Set window affinity to current virtual desktop (Windows only)."""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Get window handle from Tkinter
            hwnd = self.winfo_id()
            
            # Load user32.dll
            user32 = ctypes.WinDLL('user32', use_last_error=True)
            
            # Define constants
            HWND_TOP = 0
            SWP_NOSIZE = 0x0001
            SWP_NOMOVE = 0x0002
            SWP_NOZORDER = 0x0004
            SWP_NOACTIVATE = 0x0010
            # Constants for virtual desktop affinity (Windows 10+)
            WDA_MONITOR = 0x00000001
            WDA_EXCLUDEFROMCAPTURE = 0x00000010
            
            # Define functions
            user32.GetWindowRect.restype = wintypes.BOOL
            user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
            
            user32.SetWindowPos.restype = wintypes.BOOL
            user32.SetWindowPos.argtypes = [
                wintypes.HWND, wintypes.HWND, wintypes.INT, wintypes.INT,
                wintypes.INT, wintypes.INT, wintypes.UINT
            ]
            
            user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
            user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
            
            # Try to set desktop affinity
            # First, try SetWindowDisplayAffinity (available on Windows 10 1607 and later)
            try:
                if user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR):
                    print("Successfully set window display affinity to current monitor/desktop")
                else:
                    raise ctypes.WinError(ctypes.get_last_error())
            except Exception as e:
                print(f"SetWindowDisplayAffinity failed: {e}")
                # Fallback approach - try setting window style to be app-specific
                user32.GetWindowLongPtrW.restype = wintypes.LPARAM
                user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, wintypes.INT]
                
                user32.SetWindowLongPtrW.restype = wintypes.LPARAM
                user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, wintypes.INT, wintypes.LPARAM]
                
                # Get current extended style
                GWL_EXSTYLE = -20
                WS_EX_APPWINDOW = 0x00040000
                WS_EX_TOOLWINDOW = 0x00000080
                
                current_style = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
                
                # Remove tool window style and add app window style
                new_style = (current_style & ~WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW
                
                if user32.SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new_style):
                    # Update window to apply changes
                    rect = wintypes.RECT()
                    user32.GetWindowRect(hwnd, ctypes.byref(rect))
                    user32.SetWindowPos(
                        hwnd, HWND_TOP, rect.left, rect.top,
                        rect.right - rect.left, rect.bottom - rect.top,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE
                    )
                    print("Successfully updated window style for desktop affinity")
                else:
                    raise ctypes.WinError(ctypes.get_last_error())
        
        except Exception as e:
            # If this fails (e.g., not Windows), just continue - it's a best-effort fix
            print(f"Failed to set window desktop affinity: {e}")

    def setup_styling(self):
        """Configure ttk styles for modern dark theme."""
        style = ttk.Style()
        # Use clam theme for better customization
        style.theme_use('clam')

        # Color palette
        self.colors = {
            "bg_main": "#111827",
            "bg_sidebar": "#0F172A",
            "bg_content": "#1F2937",
            "bg_card": "#1E293B",
            "accent": "#3B82F6",
            "danger": "#EF4444",
            "success": "#22C55E",
            "text_primary": "#F9FAFB",
            "text_secondary": "#9CA3AF"
        }

        # Root window background
        self.configure(bg=self.colors["bg_main"])

        # Global styles
        style.configure("TLabel",
                        font=("Arial", 10),
                        background=self.colors["bg_main"],
                        foreground=self.colors["text_primary"])
        style.configure("TFrame",
                        background=self.colors["bg_main"])
        style.configure("TButton",
                        font=("Arial", 10),
                        padding=[10, 5],
                        relief="flat",
                        borderwidth=0,
                        background=self.colors["bg_card"],
                        foreground=self.colors["text_primary"])
        style.map("TButton",
                  background=[('active', self.colors["accent"]),
                              ('disabled', self.colors["bg_main"])],
                  foreground=[('active', self.colors["text_primary"]),
                              ('disabled', self.colors["text_secondary"])])

        # Entry
        style.configure("TEntry",
                        font=("Arial", 10),
                        fieldbackground=self.colors["bg_card"],
                        foreground=self.colors["text_primary"],
                        insertcolor=self.colors["text_primary"],
                        borderwidth=0,
                        background=self.colors["bg_main"])
        style.map("TEntry",
                  fieldbackground=[('focus', self.colors["bg_card"])])

        # LabelFrame
        style.configure("TLabelframe",
                        background=self.colors["bg_main"],
                        foreground=self.colors["text_primary"],
                        borderwidth=0,
                        relief="flat")
        style.configure("TLabelframe.Label",
                        background=self.colors["bg_main"],
                        foreground=self.colors["text_primary"],
                        font=("Arial", 10, "bold"))

        # Treeview
        style.configure("Treeview",
                        rowheight=28,
                        font=("Arial", 10),
                        background=self.colors["bg_card"],
                        foreground=self.colors["text_primary"],
                        fieldbackground=self.colors["bg_card"],
                        borderwidth=0)
        style.map("Treeview",
                  background=[('selected', self.colors["accent"])],
                  foreground=[('selected', self.colors["text_primary"])])
        style.configure("Treeview.Heading",
                        font=("Arial", 10, "bold"),
                        background=self.colors["bg_content"],
                        foreground=self.colors["text_primary"],
                        borderwidth=0,
                        relief="flat")
        style.map("Treeview.Heading",
                  background=[('active', self.colors["accent"])])

        # Scrollbar (vertical and horizontal) - increased size for better usability
        style.configure("Vertical.TScrollbar",
                        background=self.colors["bg_main"],
                        troughcolor=self.colors["bg_main"],
                        bordercolor=self.colors["bg_main"],
                        arrowcolor=self.colors["text_primary"],
                        width=14)  # Increased width for easier grabbing
        style.map("Vertical.TScrollbar",
                  background=[('active', self.colors["accent"])])
        style.configure("Horizontal.TScrollbar",
                        background=self.colors["bg_main"],
                        troughcolor=self.colors["bg_main"],
                        bordercolor=self.colors["bg_main"],
                        arrowcolor=self.colors["text_primary"],
                        height=14)  # Increased height for easier grabbing
        style.map("Horizontal.TScrollbar",
                  background=[('active', self.colors["accent"])])

        # Checkbutton
        style.configure("TCheckbutton",
                        background=self.colors["bg_main"],
                        foreground=self.colors["text_primary"])
        style.map("TCheckbutton",
                  background=[('active', self.colors["bg_card"])])

        # Sidebar specific styles
        style.configure("TSidebar.TFrame",
                        background=self.colors["bg_sidebar"])
        style.configure("TSidebar.TButton",
                        font=("Arial", 10),
                        background=self.colors["bg_sidebar"],
                        foreground=self.colors["text_primary"],
                        padding=[16, 12],
                        anchor=tk.CENTER,
                        relief="flat",
                        borderwidth=0)
        style.map("TSidebar.TButton",
                  background=[('active', self.colors["bg_main"]),
                              ('selected', self.colors["accent"])])

    def setup_ui(self):
        """Set up the main UI components with modern design."""
        # Slim header
        header_frame = ttk.Frame(self, height=45)
        header_frame.pack(fill=tk.X, expand=False, side=tk.TOP)
        header_frame.pack_propagate(False)
        
        title_label = ttk.Label(header_frame,
                                text="TaskPortKiller",
                                font=("Arial", 12, "bold"))
        title_label.pack(side=tk.LEFT, padx=15, pady=10)
        
        version_label = ttk.Label(header_frame,
                                  text="v1.0.0",
                                  font=("Arial", 8),
                                  foreground=self.colors["text_secondary"])
        version_label.pack(side=tk.LEFT, padx=5, pady=10)

        # Main content container
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        # Left sidebar navigation
        sidebar = ttk.Frame(main_container, width=180, style="TSidebar.TFrame")
        sidebar.pack(fill=tk.Y, expand=False, side=tk.LEFT)
        
        # Configure sidebar style
        style = ttk.Style()
        style.configure("TSidebar.TFrame", background=self.colors["bg_sidebar"])
        style.configure("TSidebar.TButton", background=self.colors["bg_sidebar"], foreground=self.colors["text_primary"],
                       font=("Arial", 10), padding=[16, 12], anchor=tk.CENTER)
        style.map("TSidebar.TButton",
                  background=[('active', self.colors["bg_main"]), ('selected', self.colors["accent"])])

        # Sidebar buttons container for vertical centering
        sidebar_buttons_container = ttk.Frame(sidebar, style="TSidebar.TFrame")
        sidebar_buttons_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=16)
        
        # Sidebar buttons
        self.sidebar_buttons = []
        
        ports_btn = ttk.Button(sidebar_buttons_container,
                              text="🔌 Ports",
                              style="TSidebar.TButton",
                              command=lambda: self.show_tab("ports"))
        ports_btn.pack(fill=tk.X, expand=False, padx=0, pady=8)
        self.sidebar_buttons.append((ports_btn, "ports"))
        
        processes_btn = ttk.Button(sidebar_buttons_container,
                                  text="⚡ Processes",
                                  style="TSidebar.TButton",
                                  command=lambda: self.show_tab("processes"))
        processes_btn.pack(fill=tk.X, expand=False, padx=0, pady=8)
        self.sidebar_buttons.append((processes_btn, "processes"))
        
        quick_kill_btn = ttk.Button(sidebar_buttons_container,
                                    text="💀 Quick Kill",
                                    style="TSidebar.TButton",
                                    command=lambda: self.show_tab("quick_kill"))
        quick_kill_btn.pack(fill=tk.X, expand=False, padx=0, pady=8)
        self.sidebar_buttons.append((quick_kill_btn, "quick_kill"))

        # Right content area
        content_area = ttk.Frame(main_container)
        content_area.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)

        # Show All Processes Checkbox
        control_frame = ttk.Frame(content_area, padding="16")
        control_frame.pack(fill=tk.X, expand=False)
        
        self.show_all_processes_var = tk.BooleanVar(value=False)
        show_all_check = ttk.Checkbutton(
            control_frame,
            text="Show All Processes (including system processes)",
            variable=self.show_all_processes_var,
            command=self.on_show_all_processes_toggle
        )
        show_all_check.pack(side=tk.LEFT)

        # Content tabs container
        self.tabs_container = ttk.Frame(content_area)
        self.tabs_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        # Create tabs
        self.ports_tab = PortsTab(self.tabs_container)
        self.processes_tab = ProcessesTab(self.tabs_container)
        self.quick_kill_tab = QuickKillTab(self.tabs_container)

        # Hide all tabs initially
        self.ports_tab.container.pack_forget()
        self.processes_tab.container.pack_forget()
        self.quick_kill_tab.container.pack_forget()

        # Show default tab
        self.current_tab = None
        self.show_tab("quick_kill")

        # Status bar
        status_bar = ttk.Frame(self, height=30)
        status_bar.pack(fill=tk.X, expand=False, side=tk.BOTTOM)
        status_bar.pack_propagate(False)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(status_bar, textvariable=self.status_var, font=("Arial", 9))
        status_label.pack(side=tk.LEFT, padx=15, pady=5)

        # Configure scrolledtext colors
        self.quick_kill_tab.preview_text.configure(bg=self.colors["bg_card"], fg=self.colors["text_primary"])
        self.quick_kill_tab.results_text.configure(bg=self.colors["bg_card"], fg=self.colors["text_primary"])

    def show_tab(self, tab_name):
        """Show selected tab and update sidebar button states."""
        if self.current_tab == tab_name:
            return

        # Hide all tabs
        self.ports_tab.container.pack_forget()
        self.processes_tab.container.pack_forget()
        self.quick_kill_tab.container.pack_forget()

        # Show selected tab
        if tab_name == "ports":
            self.ports_tab.container.pack(fill=tk.BOTH, expand=True)
        elif tab_name == "processes":
            self.processes_tab.container.pack(fill=tk.BOTH, expand=True)
        elif tab_name == "quick_kill":
            self.quick_kill_tab.container.pack(fill=tk.BOTH, expand=True)

        # Update button styles
        for btn, btn_tab in self.sidebar_buttons:
            if btn_tab == tab_name:
                btn.state(['selected'])
            else:
                btn.state(['!selected'])

        self.current_tab = tab_name

    def on_show_all_processes_toggle(self):
        """Callback for show all processes checkbox toggle."""
        # Refresh both tabs to reflect the new state
        self.ports_tab.refresh_ports()
        self.processes_tab.refresh_processes()

    def on_exit(self):
        """Handle application exit."""
        if ask_confirmation("Exit", "Are you sure you want to exit TaskPortKiller?"):
            self.destroy()

    def update_status(self, message: str, timeout=3000):
        """Update status bar."""
        self.status_var.set(message)
        self.after(timeout, lambda: self.status_var.set("Ready"))


# ==============================
# Application Entry Point
# ==============================
def check_psutil():
    """Check if psutil is installed."""
    try:
        import psutil
        return True
    except ImportError:
        return False


def main():
    """Main application entry point."""
    print("=" * 60)
    print("TaskPortKiller v1.0.0")
    print("=" * 60)
    print()

    if not check_psutil():
        print("ERROR: psutil library not found!")
        print()
        print("Please install psutil by running:")
        print("  pip install psutil")
        print()
        print("Press any key to exit...")
        input()
        sys.exit(1)

    print("Initializing TaskPortKiller...")
    print("Loading user interface...")
    print()

    try:
        app = MainApplication()
        app.mainloop()
    except Exception as e:
        print(f"Fatal error: {e}")
        show_error("Fatal Error", f"Application failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()