#!/usr/bin/env bash
# format-stream.sh — Format Claude Code stream-json into readable stdout
#
# Reads JSON lines from stdin, extracts tool calls and text, prints a
# human-readable activity log. Uses jq when available, falls back to
# bash regex (best-effort — may miss fields with escaped quotes or
# reordered keys).

# Detect jq availability once
_has_jq=false
command -v jq &>/dev/null && _has_jq=true

# Extract a string field from a JSON line.
# Usage: _json_field "fieldname" "$line"
_json_field() {
    local field="$1" line="$2"
    if $_has_jq; then
        echo "$line" | jq -r "first(.. | .${field}? // empty)" 2>/dev/null
    else
        # Fallback: regex match (fragile with escaped quotes)
        if [[ "$line" =~ \"${field}\":\"([^\"]+)\" ]]; then
            echo "${BASH_REMATCH[1]}"
        fi
    fi
}

# Extract a numeric field from a JSON line.
_json_num() {
    local field="$1" line="$2"
    if $_has_jq; then
        echo "$line" | jq -r "first(.. | .${field}? // empty)" 2>/dev/null
    else
        if [[ "$line" =~ \"${field}\":([0-9.]+) ]]; then
            echo "${BASH_REMATCH[1]}"
        fi
    fi
}

while IFS= read -r line; do
    # Skip empty lines
    [[ -z "$line" ]] && continue

    type="$(_json_field "type" "$line")"

    case "$type" in
        system)
            model="$(_json_field "model" "$line")"
            [[ -n "$model" ]] && echo "  [init] model=${model}"
            ;;
        assistant)
            tool_name="$(_json_field "name" "$line")"
            if [[ -n "$tool_name" ]]; then
                case "$tool_name" in
                    Read|Write|Edit)
                        fp="$(_json_field "file_path" "$line")"
                        [[ -n "$fp" ]] && echo "  [${tool_name,,}] ${fp}"
                        ;;
                    Bash)
                        cmd="$(_json_field "command" "$line")"
                        if [[ -n "$cmd" ]]; then
                            cmd="${cmd//\\n/ }"
                            echo "  [bash] ${cmd:0:120}"
                        fi
                        ;;
                    Grep|Glob)
                        pat="$(_json_field "pattern" "$line")"
                        [[ -n "$pat" ]] && echo "  [${tool_name,,}] ${pat}"
                        ;;
                    *)
                        echo "  [${tool_name}]"
                        ;;
                esac
            else
                text="$(_json_field "text" "$line")"
                if [[ -n "$text" ]] && [[ ${#text} -gt 20 ]]; then
                    text="${text//\\n/ }"
                    echo "  [text] ${text:0:120}..."
                fi
            fi
            ;;
        result)
            cost="$(_json_num "total_cost_usd" "$line")"
            duration="$(_json_num "duration_ms" "$line")"
            turns="$(_json_num "num_turns" "$line")"
            echo "  [done] ${turns:-?} turns, ${duration:-?}ms, \$${cost:-?}"
            ;;
    esac
done
