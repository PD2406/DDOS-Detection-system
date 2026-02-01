#!/usr/bin/env python3
"""
DDoS Detection System Startup Script
Starts both the API server and dashboard
"""

import subprocess
import sys
import time
import os
import signal
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import fastapi
        import uvicorn
        import streamlit
        import scapy
        print("✅ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Run: pip install -r requirements.txt")
        return False

def start_api_server():
    """Start the FastAPI server"""
    print("🚀 Starting DDoS Detection API Server...")
    api_process = subprocess.Popen([
        sys.executable, "run.py",
        "--host", "0.0.0.0",
        "--port", "8000"
    ], cwd=os.getcwd())

    # Wait a bit for server to start
    time.sleep(3)

    # Check if server started successfully
    if api_process.poll() is None:
        print("✅ API Server started on http://localhost:8000")
        print("📚 API Docs: http://localhost:8000/docs")
        print("🔄 API Redoc: http://localhost:8000/redoc")
        return api_process
    else:
        print("❌ Failed to start API server")
        return None

def start_dashboard():
    """Start the Streamlit dashboard"""
    print("📊 Starting DDoS Detection Dashboard...")
    dashboard_process = subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", "dashboard/app.py",
        "--server.port", "8501",
        "--server.address", "0.0.0.0"
    ], cwd=os.getcwd())

    # Wait a bit for dashboard to start
    time.sleep(2)

    # Check if dashboard started successfully
    if dashboard_process.poll() is None:
        print("✅ Dashboard started on http://localhost:8501")
        return dashboard_process
    else:
        print("❌ Failed to start dashboard")
        return None

def main():
    """Main startup function"""
    print("=" * 60)
    print("🛡️  DDoS Detection System Startup")
    print("=" * 60)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    processes = []

    try:
        # Start API server
        api_process = start_api_server()
        if api_process:
            processes.append(("API Server", api_process))

        # Start dashboard
        dashboard_process = start_dashboard()
        if dashboard_process:
            processes.append(("Dashboard", dashboard_process))

        if not processes:
            print("❌ Failed to start any services")
            sys.exit(1)

        print("\n" + "=" * 60)
        print("🎉 System started successfully!")
        print("=" * 60)
        print("🌐 Services running:")
        for name, process in processes:
            print(f"   • {name}: PID {process.pid}")

        print("\n📋 Access URLs:")
        print("   • API Server: http://localhost:8000")
        print("   • API Docs: http://localhost:8000/docs")
        print("   • Dashboard: http://localhost:8501")
        print("\n🛑 Press Ctrl+C to stop all services")

        # Keep running until interrupted
        while True:
            time.sleep(1)

            # Check if any process died
            for name, process in processes:
                if process.poll() is not None:
                    print(f"❌ {name} process died (exit code: {process.returncode})")
                    # Kill remaining processes
                    for n, p in processes:
                        if p.poll() is None:
                            p.terminate()
                    sys.exit(1)

    except KeyboardInterrupt:
        print("\n🛑 Shutting down services...")
        for name, process in processes:
            if process.poll() is None:
                print(f"   • Stopping {name}...")
                process.terminate()

        # Wait for processes to terminate
        time.sleep(2)
        for name, process in processes:
            if process.poll() is None:
                process.kill()

        print("✅ All services stopped")
        sys.exit(0)

if __name__ == "__main__":
    main()
