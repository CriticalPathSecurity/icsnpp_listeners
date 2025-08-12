#!/bin/bash

# ICSNPP Listeners Daemon Management Script
# Usage: ./icsnpp_daemon.sh {start|stop|restart|status}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/run_listeners.py"
PID_FILE="/tmp/icsnpp_listeners.pid"
LOG_FILE="/tmp/icsnpp_listeners.log"

start() {
    # Check if already running
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "ICSNPP listeners already running (PID: $PID)"
            return 1
        else
            echo "Removing stale PID file"
            rm -f "$PID_FILE"
        fi
    fi
    
    # Ensure we can write to the PID file location
    PID_DIR=$(dirname "$PID_FILE")
    if [ ! -w "$PID_DIR" ]; then
        echo "Error: Cannot write to PID file directory: $PID_DIR"
        echo "Please run as root or change PID_FILE location"
        return 1
    fi
    
    # Ensure we can write to the log file location
    LOG_DIR=$(dirname "$LOG_FILE")
    if [ ! -w "$LOG_DIR" ]; then
        echo "Error: Cannot write to log file directory: $LOG_DIR"
        echo "Please run as root or change LOG_FILE location"
        return 1
    fi
    
    echo "Starting ICSNPP listeners..."
    
    # Check if Python3 is available
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: python3 not found in PATH"
        return 1
    fi
    
    # Check if the Python script exists
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        echo "Error: Python script not found: $PYTHON_SCRIPT"
        return 1
    fi
    
    # Start the service
    nohup python3 "$PYTHON_SCRIPT" \
        --daemon \
        --pid-file "$PID_FILE" \
        --log-level INFO \
        --log-connections \
        --quiet \
        > "$LOG_FILE" 2>&1 &
    
    # Give it time to start and create PID file
    sleep 3
    
    # Check if the service started successfully
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "ICSNPP listeners started successfully (PID: $PID)"
            echo "Log file: $LOG_FILE"
            return 0
        else
            echo "Process died after startup (PID: $PID)"
            echo "Check log file for errors: $LOG_FILE"
            if [ -f "$LOG_FILE" ]; then
                echo "Last 10 lines of log:"
                tail -n 10 "$LOG_FILE"
            fi
            return 1
        fi
    else
        echo "Failed to create PID file: $PID_FILE"
        echo "This could be due to:"
        echo "  - Permission issues (try running as root)"
        echo "  - Python script startup error"
        echo "  - Missing dependencies"
        if [ -f "$LOG_FILE" ]; then
            echo "Check log file for details: $LOG_FILE"
            echo "Last 20 lines of log:"
            tail -n 20 "$LOG_FILE"
        fi
        return 1
    fi
}

stop() {
    if [ ! -f "$PID_FILE" ]; then
        echo "ICSNPP listeners not running (no PID file)"
        return 0
    fi
    
    PID=$(cat "$PID_FILE")
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "ICSNPP listeners not running (stale PID file)"
        rm -f "$PID_FILE"
        return 0
    fi
    
    echo "Stopping ICSNPP listeners (PID: $PID)..."
    kill -TERM "$PID"
    
    # Wait up to 10 seconds for graceful shutdown
    for i in {1..10}; do
        if ! kill -0 "$PID" 2>/dev/null; then
            echo "ICSNPP listeners stopped successfully"
            rm -f "$PID_FILE"
            return 0
        fi
        sleep 1
    done
    
    echo "Force killing ICSNPP listeners..."
    kill -KILL "$PID" 2>/dev/null
    rm -f "$PID_FILE"
    echo "ICSNPP listeners forcibly stopped"
}

status() {
    if [ ! -f "$PID_FILE" ]; then
        echo "ICSNPP listeners: NOT RUNNING"
        return 1
    fi
    
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "ICSNPP listeners: RUNNING (PID: $PID)"
        
        # Show port usage
        echo "Active listeners:"
        netstat -tlnp 2>/dev/null | grep "$PID" | awk '{print "  " $1 " " $4}' || \
        lsof -p "$PID" 2>/dev/null | grep LISTEN | awk '{print "  TCP " $9}'
        return 0
    else
        echo "ICSNPP listeners: NOT RUNNING (stale PID file)"
        rm -f "$PID_FILE"
        return 1
    fi
}

restart() {
    stop
    sleep 2
    start
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        echo
        echo "Commands:"
        echo "  start   - Start ICSNPP listeners as daemon"
        echo "  stop    - Stop ICSNPP listeners"
        echo "  restart - Restart ICSNPP listeners"
        echo "  status  - Check if ICSNPP listeners are running"
        echo
        echo "Files:"
        echo "  PID file: $PID_FILE"
        echo "  Log file: $LOG_FILE"
        exit 1
        ;;
esac

exit $?
