#!/bin/bash
# Docker-based scanner helper script for CI/CD pipelines

# Build the Docker image if needed
if [[ "$1" == "--build" ]]; then
    echo "Building Docker image..."
    docker build -t agent-security .
    shift
fi

# Check if target is provided
if [[ -z "$1" ]]; then
    echo "Error: No target specified."
    echo "Usage: $0 [--build] <target> [options]"
    echo "Example: $0 ./src --output-csv results.csv"
    exit 1
fi

TARGET="$1"
shift

# Determine if target is a Git repository or local path
if [[ "$TARGET" == http* ]] || [[ "$TARGET" == git://* ]]; then
    # For Git repositories, no volume mount needed
    echo "Scanning Git repository: $TARGET"
    docker run --rm agent-security "$TARGET" "$@"
else
    # For local files/directories, mount as volume
    ABSOLUTE_PATH=$(realpath "$TARGET")
    
    if [[ -f "$ABSOLUTE_PATH" ]]; then
        # Single file
        DIRNAME=$(dirname "$ABSOLUTE_PATH")
        FILENAME=$(basename "$ABSOLUTE_PATH")
        echo "Scanning file: $FILENAME"
        docker run --rm -v "$DIRNAME:/scan" agent-security "$FILENAME" "$@"
    elif [[ -d "$ABSOLUTE_PATH" ]]; then
        # Directory
        echo "Scanning directory: $ABSOLUTE_PATH"
        docker run --rm -v "$ABSOLUTE_PATH:/scan" agent-security /scan "$@"
    else
        echo "Error: Target '$TARGET' is not a valid file or directory."
        exit 1
    fi
fi 