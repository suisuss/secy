#!/usr/bin/env bash
# format-stream.sh — Format Claude Code stream-json into readable stdout
#
# Reads JSON lines from stdin, extracts tool calls and text, prints a
# human-readable activity log. Requires no dependencies beyond bash and
# basic string ops (no jq needed in the container).

while IFS= read -r line; do
    # Skip empty lines
    [[ -z "$line" ]] && continue

    # Extract type field
    type=""
    if [[ "$line" =~ \"type\":\"([^\"]+)\" ]]; then
        type="${BASH_REMATCH[1]}"
    fi

    case "$type" in
        system)
            # Init message — show model
            if [[ "$line" =~ \"model\":\"([^\"]+)\" ]]; then
                echo "  [init] model=${BASH_REMATCH[1]}"
            fi
            ;;
        assistant)
            # Check for tool_use
            if [[ "$line" =~ \"name\":\"([^\"]+)\" ]]; then
                tool_name="${BASH_REMATCH[1]}"
                # Extract relevant input based on tool
                case "$tool_name" in
                    Read)
                        if [[ "$line" =~ \"file_path\":\"([^\"]+)\" ]]; then
                            echo "  [read] ${BASH_REMATCH[1]}"
                        fi
                        ;;
                    Write)
                        if [[ "$line" =~ \"file_path\":\"([^\"]+)\" ]]; then
                            echo "  [write] ${BASH_REMATCH[1]}"
                        fi
                        ;;
                    Bash)
                        if [[ "$line" =~ \"command\":\"([^\"]{1,120}) ]]; then
                            cmd="${BASH_REMATCH[1]}"
                            # Unescape basic JSON
                            cmd="${cmd//\\n/ }"
                            cmd="${cmd//\\\"/\"}"
                            echo "  [bash] ${cmd}"
                        fi
                        ;;
                    Grep)
                        if [[ "$line" =~ \"pattern\":\"([^\"]+)\" ]]; then
                            echo "  [grep] ${BASH_REMATCH[1]}"
                        fi
                        ;;
                    Glob)
                        if [[ "$line" =~ \"pattern\":\"([^\"]+)\" ]]; then
                            echo "  [glob] ${BASH_REMATCH[1]}"
                        fi
                        ;;
                    Edit)
                        if [[ "$line" =~ \"file_path\":\"([^\"]+)\" ]]; then
                            echo "  [edit] ${BASH_REMATCH[1]}"
                        fi
                        ;;
                    *)
                        echo "  [${tool_name}]"
                        ;;
                esac
            elif [[ "$line" =~ \"text\":\"([^\"]{1,200}) ]]; then
                # Assistant text (truncated for readability)
                text="${BASH_REMATCH[1]}"
                text="${text//\\n/ }"
                # Only show if it looks like meaningful commentary, not just "I'll read..."
                if [[ ${#text} -gt 20 ]]; then
                    echo "  [text] ${text:0:120}..."
                fi
            fi
            ;;
        result)
            # Final result — show cost and duration
            cost=""
            duration=""
            turns=""
            if [[ "$line" =~ \"total_cost_usd\":([0-9.]+) ]]; then
                cost="${BASH_REMATCH[1]}"
            fi
            if [[ "$line" =~ \"duration_ms\":([0-9]+) ]]; then
                duration="${BASH_REMATCH[1]}"
            fi
            if [[ "$line" =~ \"num_turns\":([0-9]+) ]]; then
                turns="${BASH_REMATCH[1]}"
            fi
            echo "  [done] ${turns} turns, ${duration}ms, \$${cost}"
            ;;
    esac
done
