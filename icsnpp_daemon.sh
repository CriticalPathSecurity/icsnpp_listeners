#!/bin/bash

# ICSNPP Listeners Daemon Management Script
# Usage: ./icsnpp_daemon.sh {start|stop|restart|status}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/run_listeners.py"
PID_FILE="/tmp/icsnpp_listeners.pid"
LOG_FILE="/tmp/icsnpp_listeners.log"

start() {
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
    
    echo "Starting ICSNPP listeners..."
    nohup python3 "$PYTHON_SCRIPT" \
        --daemon \
        --pid-file "$PID_FILE" \
        --log-level INFO \
        --log-connections \
        --quiet \
        > "$LOG_FILE" 2>&1 &
    
    sleep 2
    
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "ICSNPP listeners started successfully (PID: $PID)"
            echo "Log file: $LOG_FILE"
            return 0
        else
            echo "Failed to start ICSNPP listeners"
            cat "$LOG_FILE"
            return 1
        fi
    else
        echo "Failed to create PID file"
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
