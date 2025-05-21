#!/bin/bash
# Docker-based scanner helper script for CI/CD pipelines

# Help text function
show_help() {
    echo "Usage: $0 [--build] <target> [options]"
    echo ""
    echo "Examples:"
    echo "  $0 my_agent.yaml"
    echo "  $0 /full/path/to/my_agent.yaml"
    echo "  $0 ./my_agents_directory"
    echo "  $0 --build ./my_agent.yaml    # Build container first, then scan"
    echo ""
    echo "This script will scan your local files or directories for agent security issues"
    echo "using the agent-security Docker container."
    exit 1
}

# Show help if no arguments or help flag
if [[ "$1" == "" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
fi

# Build the Docker image if needed
if [[ "$1" == "--build" ]]; then
    echo "Building Docker image..."
    docker build -t agent-security .
    shift
fi

# Check if target is provided
if [[ -z "$1" ]]; then
    echo "Error: No target specified."
    show_help
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
        docker run --rm -v "$DIRNAME:/scan" agent-security "/scan/$FILENAME" "$@"
    elif [[ -d "$ABSOLUTE_PATH" ]]; then
        # Directory
        echo "Scanning directory: $ABSOLUTE_PATH"
        docker run --rm -v "$ABSOLUTE_PATH:/scan" agent-security /scan "$@"
    else
        echo "Error: Target '$TARGET' is not a valid file or directory."
        exit 1
    fi
fi 