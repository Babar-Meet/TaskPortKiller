# TaskPortKiller

Professional Ports and Processes Management Tool for Windows

## Overview

TaskPortKiller is a modern, professional-grade desktop application designed to help you manage your Windows system's listening ports and running processes with ease. The application provides a clean, intuitive interface with comprehensive functionality and robust error handling.

## Features

TaskPortKiller offers comprehensive port and process management capabilities with a focus on usability, safety, and performance.

### 🚀 Core Functionality

#### Ports Management
- **Real-time Listening Ports Display**: Shows all active listening ports on your system with detailed information
- **Process Association**: Displays which process is using each port (PID and process name)
- **Kill Process Functionality**: Terminate processes using specific ports with comprehensive safety checks
- **Search and Filtering**: Quick search for ports by protocol, IP address, port number, or process name
- **Auto Refresh**: Automatically updates port list every 3 seconds (configurable)
- **Manual Refresh**: One-click refresh for immediate updates
- **Safety Checks**: Prevents killing system processes and the application itself

#### Processes Management
- **Process Discovery**: View all non-system processes running on your system
- **Detailed Process Information**: Shows PID, process name, CPU usage, memory usage, thread count, status, username, and command line
- **Kill Functionality**: Terminate processes with confirmation dialog to prevent accidental deletion
- **Search and Filtering**: Search processes by PID, name, username, status, or command line
- **Sortable Columns**: Click on column headers to sort processes by any field
- **Auto Refresh**: Automatically updates process list every 3 seconds (configurable)
- **Manual Refresh**: One-click refresh for immediate updates
- **Comprehensive Safety**: Prevents killing critical system processes

### 🛡️ Safety Features

- **Critical Process Protection**: Automatically ignores and prevents killing of system processes, critical Windows processes (csrss.exe, wininit.exe, services.exe, lsass.exe), services processes (svchost.exe), and processes from protected directories (C:\Windows, Program Files, System32, etc.)
- **User Confirmation**: All kill operations require explicit user confirmation
- **Anti-Dumb Protection**: Prevents accidental killing of critical processes and the application itself
- **Permission Handling**: Gracefully handles access denied errors and权限 issues

### 💎 User Experience

- **Modern UI**: Professional ttk-styled interface with clean, intuitive design
- **Threaded Refresh**: Background refresh operations to prevent UI freezing
- **Real-time Status**: Displays current status and last refresh time
- **Responsive Design**: Supports window resizing and adaptive layout
- **Comprehensive Error Handling**: Detailed error messages and handling for various system errors
- **Search Highlighting**: Find matching results instantly with search functionality

### 📊 Technical Capabilities

- **System Resource Monitoring**: CPU and memory usage tracking for processes
- **Process Details**: Access to comprehensive process information including command line arguments
- **Port Information**: Detailed port data including protocol, local IP, and process association
- **Performance Optimized**: Efficient process and port discovery with minimal system impact
- **Background Processing**: Refresh operations run in separate threads for smooth UI experience

## Installation & Setup

### For General Users (No Coding Required)


#### Using build_exe.bat (Recommended)

The easiest way to build the executable is using the `build_exe.bat` script, which automates the entire process:

1. **Run the Build Script**
   - Double-click `build_exe.bat` from File Explorer
   - Or run it from Command Prompt:
     ```bash
     build_exe.bat
     ```

2. **What to Expect During Build**
   The script will guide you through the process:
   - Display a welcome message and wait for your confirmation
   - Check if Python is properly installed
   - Create a temporary virtual environment (`build_env`)
   - Install required dependencies and PyInstaller
   - Clean previous build artifacts
   - Build the executable with PyInstaller
   - Clean up temporary files
   - Show success message with the executable location

3. **Result**
   A standalone executable `TaskPortKiller.exe` will be created in the `dist` folder. This file can be run on any Windows computer without Python.


If you're not a developer and just want to use the application:

1. **Download the Application**
   - You'll need the `run app for devs` folder which contains the necessary scripts

2. **Run the Installation Script**
   - Double-click on `run app for devs/install.bat`
   - This will automatically:
     - Check if Python is installed
     - Install the required `psutil` library if it's missing
     - Provide instructions for running the application

3. **Launch the Application**
   - Double-click on `run app for devs/run_app.bat`
   - This will automatically:
     - Check Python installation
     - Verify dependencies
     - Launch TaskPortKiller

### For Developers (Development Environment Setup)

If you want to modify or contribute to the code:

#### Prerequisites
- Python 3.7 or higher
- Windows 10 or Windows 11
- Git (for version control)

#### Step 1: Clone or Download the Project
- Download the project files to your local machine

#### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```
or
```bash
pip install psutil
```

#### Step 3: Run the Application
```bash
python main.py
```

#### Step 4: Build Executable (Optional)

For users who want to create a standalone executable that can run on any Windows computer without Python installed, follow these detailed instructions:

### Building the Executable

#### Prerequisites
Before you begin, ensure your system meets these requirements:

1. **Python Installation**
   - Python 3.6 or higher (Python 3.7+ recommended)
   - Must be added to system PATH (check "Add Python to PATH" during installation)

2. **System Requirements**
   - Windows 10 or Windows 11 (32-bit or 64-bit)
   - At least 500MB free disk space for temporary build files
   - Administrator privileges (for some operations)

#### Manual Build Instructions (Alternative)

If you prefer to build manually:

1. **Install PyInstaller**
   ```bash
   pip install pyinstaller
   ```

2. **Clean Previous Builds (Optional but Recommended)**
   ```bash
   if exist build rmdir /s /q build
   if exist dist rmdir /s /q dist
   if exist TaskPortKiller.spec del TaskPortKiller.spec
   ```

3. **Build the Executable**
   - For windowed application (no console):
     ```bash
     pyinstaller --onefile --windowed --name=TaskPortKiller --distpath=dist main.py
     ```

   - If you have an icon file (icon.ico):
     ```bash
     pyinstaller --onefile --windowed --icon=icon.ico --name=TaskPortKiller --distpath=dist main.py
     ```

   - For console output (debugging):
     ```bash
     pyinstaller --onefile --name=TaskPortKiller --distpath=dist main.py
     ```

4. **Locate the Executable**
   The `TaskPortKiller.exe` file will be in the `dist` folder.

#### Build Process Details

The build script (`build_exe.bat`) performs these key steps:

1. **Environment Setup**: Creates a temporary virtual environment to isolate the build process
2. **Dependency Installation**: Installs required packages and PyInstaller
3. **Cleanup**: Removes previous build artifacts
4. **Compilation**: Packages your Python script and dependencies into a single executable
5. **Cleanup**: Removes temporary files

#### Troubleshooting Common Build Issues

**1. "Python is not installed!" Error**
- Install Python from [python.org](https://www.python.org/)
- Ensure you check "Add Python to PATH" during installation
- Restart your terminal or computer

**2. "pyinstaller is not recognized" Error**
- Try reinstalling PyInstaller:
  ```bash
  pip install --upgrade pyinstaller
  ```
- Check if Python's Scripts directory is in your PATH

**3. Build Fails with "Permission Denied"**
- Run Command Prompt as Administrator
- Close any open TaskPortKiller processes
- Temporarily disable antivirus software that might be interfering

**4. Build Succeeds but EXE Doesn't Run**
- Check if `main.py` exists in the correct directory
- Verify Python installation
- Try running without the `--windowed` option to see console errors

**5. Large Executable Size**
- The executable includes Python runtime and dependencies, so it's normal (typically ~15-25MB)
- This is unavoidable for standalone executables

**6. Missing icon.ico**
- If you don't have an icon file, the build will continue without it
- The executable will use a default icon

**7. Virtual Environment Issues**
- Delete the `build_env` folder and try again
- Manually create and activate a virtual environment

#### Distributing the Executable

1. **Single File**: Just distribute `dist/TaskPortKiller.exe`
2. **No Dependencies**: Recipients don't need Python installed
3. **Compatibility**: Works on Windows 10 and Windows 11 (32-bit/64-bit)
4. **Portability**: Can be run from any location (USB drive, network share, etc.)

#### Verifying the Build

After building, test your executable:
1. Run `dist/TaskPortKiller.exe`
2. Verify all features work correctly
3. Check that the application starts quickly without Python errors

#### Development Tips
- Run `python test_app.py` to verify functionality
- Modify `main.py` to add or enhance features
- The application uses Tkinter with ttk styling for the UI
- Process management is handled through the `psutil` library

## Usage Guide

### Ports Tab

1. **Viewing Ports**: The main table displays all listening ports with their protocol, local IP, port number, PID, and process name
2. **Searching**: Use the search bar to filter ports by any column value
3. **Killing Processes**: Select a port and click the "Kill Process" button to terminate the process using that port
4. **Refreshing**: Click "Refresh" to manually update the port list
5. **Auto Refresh**: Toggle the "Auto Refresh (3s)" checkbox to enable/disable automatic updates

### Processes Tab

1. **Viewing Processes**: The main table shows all non-system processes with detailed information
2. **Sorting**: Click on any column header to sort the processes
3. **Searching**: Use the search bar to filter processes by any column value
4. **Killing Processes**: Select a process and click the "Kill Process" button to terminate it
5. **Refreshing**: Click "Refresh" to manually update the process list
6. **Auto Refresh**: Toggle the "Auto Refresh (3s)" checkbox to enable/disable automatic updates

## Safety Features

### Critical Process Protection
The application automatically ignores and prevents killing of:
- System processes (System, Registry, Idle)
- Critical Windows processes (csrss.exe, wininit.exe, services.exe, lsass.exe)
- Services processes (svchost.exe)
- Processes from protected directories (C:\Windows, Program Files, System32, etc.)
- The application itself

### User Confirmation
All kill operations require explicit user confirmation to prevent accidental termination.

## Technical Details

### Architecture
- **Object-Oriented Design**: Clean separation of UI and logic
- **Threading**: Background refresh operations to keep UI responsive
- **Tkinter ttk Styling**: Modern, professional interface
- **Psutil Library**: System information collection and management

### Configuration
- **Refresh Interval**: 3 seconds (can be changed in code)
- **Ignored Processes/Paths**: Configurable in the `IGNORE_PROCESSES`, `IGNORE_EXECUTABLES`, and `IGNORE_PATHS` constants
- **Special IP Addresses**: Ignore ports listening on 0.0.0.0 and :: (can be modified)

### System Requirements
- Python 3.7+
- Windows 10/11
- psutil library (v5.8.0 or higher)
- At least 512MB RAM
- 50MB free disk space

## Error Handling

The application includes comprehensive error handling for:
- Access denied errors
- Process not found errors
- Zombie processes
- System errors
- Network connection errors
- UI threading issues

## License

MIT License - feel free to use and modify as needed.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Project Structure

### File Structure
```
TaskPortKiller/
├── main.py                 # Main application executable
├── test_app.py            # Test script for verification
├── run_app.bat            # Batch file to run the application
├── install.bat            # Installation script
├── requirements.txt       # Project dependencies
└── README.md              # Project documentation
```

### Root Directory Files

#### main.py
The main application file containing:

1. **Configuration Constants** - Defines application settings like refresh interval, ignored processes, etc.
2. **Utility Functions** - Helper functions for system process checking and string sanitization
3. **Port Management Logic** - Functions to get listening ports and kill port processes
4. **Process Management Logic** - Functions to get and manage system processes
5. **UI Components** - Classes for:
   - `PortsTab` - Ports management interface
   - `ProcessesTab` - Processes management interface
   - `MainApplication` - Main application window
6. **Application Entry Point** - `main()` function to start the application

#### test_app.py
Comprehensive test script that:
- Tests module imports
- Verifies psutil installation
- Tests psutil functionality
- Tests application startup

#### run_app.bat
Windows batch file to:
- Check Python installation
- Check and install dependencies if missing
- Run the application

#### install.bat
Windows installation script to:
- Check system requirements
- Install required dependencies
- Provide instructions for running the application

#### requirements.txt
List of project dependencies:
```
psutil>=5.8.0
```

### Architecture Design

#### UI Architecture
The application uses a **Model-View-Controller (MVC) pattern** with Tkinter:
1. **MainApplication** - Manages the overall application window and orchestrates the UI
2. **PortsTab & ProcessesTab** - Act as controllers for their respective tab views
3. **Treeview Widgets** - Display the data tables with sorting capabilities
4. **Background Threading** - Handles refresh operations to prevent UI freezing
5. **ttk Styling** - Provides a modern, professional interface with consistent styling

#### Business Logic Architecture
The application is organized into logical modules:
1. **Port Management** - Handles listening ports discovery and process killing
2. **Process Management** - Manages process discovery and termination
3. **System Information** - Gathers information about system resources
4. **Safety & Security** - Implements process filtering and safety checks
5. **Error Handling** - Comprehensive error handling for all operations

#### Safety Features Architecture
The application implements several layers of safety:
1. **Process Filtering** - Automatically ignores system processes
2. **User Confirmation** - Requires explicit confirmation for kill operations
3. **Permission Checks** - Handles access denied errors gracefully
4. **Anti-Dumb Protection** - Prevents killing critical processes and the application itself

### Key Technologies
- **Python 3.7+** - Core programming language
- **Tkinter** - GUI framework with ttk styling
- **psutil** - System information and process management library
- **Threading** - Background refresh operations
- **Windows Batch Files** - Simplified deployment and installation

### Development Best Practices
1. **Object-Oriented Design** - Classes for UI components with clear responsibilities
2. **Separation of Concerns** - Logic separated from UI components
3. **Error Handling** - Comprehensive try-except blocks with user feedback
4. **Thread Safety** - Proper use of tkinter's after() method for UI operations
5. **Code Readability** - Clear documentation and well-structured code
6. **Safety First** - Comprehensive process validation before termination

### Deployment Strategy
The application is designed for easy deployment on Windows systems:
1. **Simple Installation** - One-click install via install.bat
2. **Portable** - No registry changes or system modifications
3. **Dependencies Check** - Automatically checks for required packages
4. **Simplified Execution** - Run via run_app.bat or double-click
5. **Standalone** - No additional runtime environments required

### Version Control
The application structure is designed to be version-controlled with Git, with:
- Clear file separation
- Logical module organization
- Comprehensive tests
- Installation and deployment scripts

### Future Enhancement Areas
1. **Advanced Filtering** - More complex search and filtering options
2. **Export Functionality** - Export port/process data to CSV/JSON
3. **Process Tree View** - Visual representation of process hierarchy
4. **Custom Rules** - User-configurable ignore lists
5. **Performance Metrics** - Real-time performance monitoring
6. **Remote Management** - Network port/process management

## Release Notes

### Version 1.0.0 (2026-02-16)

#### Initial Release

##### Features Implemented

1. **Modern UI Design**
   - Professional ttk-styled interface
   - Clean tabbed layout for Ports and Processes
   - Responsive design with resize support
   - Professional color scheme and styling

2. **Ports Management**
   - Real-time listening ports display
   - Process association for each port
   - Kill process functionality with safety checks
   - Search and filtering capabilities
   - Auto-refresh every 3 seconds
   - Manual refresh option

3. **Processes Management**
   - Comprehensive process list with detailed information
   - Sortable columns (PID, name, CPU, memory, etc.)
   - Search and filtering functionality
   - Kill process with confirmation dialog
   - Auto-refresh and manual refresh options
   - Process status monitoring

4. **Safety Features**
   - Automatic ignoring of system processes
   - Prevent killing critical Windows processes
   - Safety checks before terminating processes
   - User confirmation required for all kill operations
   - Prevents killing the application itself

5. **Error Handling**
   - Comprehensive error handling for all operations
   - Access denied errors gracefully handled
   - Process not found errors managed properly
   - Zombie process detection
   - Network and system error handling

6. **Performance**
   - Threaded refresh operations to prevent UI freezing
   - Efficient process and port discovery
   - Optimized memory usage
   - Background refresh for better user experience

##### Technical Details
- **Platform**: Windows 10/11
- **Language**: Python 3.7+
- **Dependencies**: psutil 5.8.0+
- **UI Framework**: Tkinter with ttk styling
- **Architecture**: Object-oriented design with MVC pattern
- **Threading**: Background refresh operations
- **Safety Checks**: Multiple layers of process validation

##### Usage Instructions
1. **Installation**: Double-click `install.bat` or run `pip install psutil`
2. **Running**: Double-click `run_app.bat` or run `python main.py`
3. **Testing**: Run `python test_app.py` to verify functionality

##### Known Limitations
- Currently Windows-only
- Requires Python installation
- May require administrator privileges for some operations
- Process tree view not implemented in this version

##### Future Enhancements
1. Advanced filtering options
2. Process tree visualization
3. Export functionality (CSV/JSON)
4. Remote management capabilities
5. Performance monitoring metrics
6. Custom ignore rules
7. Dark mode support
8. Process dependency analysis

##### Development Team
- Author: Giga Potato
- Created: February 16, 2026
- Version: 1.0.0
- License: MIT
