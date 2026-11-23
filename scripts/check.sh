#!/usr/bin/env bash
set -euo pipefail

build_dir=/build/debug
configure() {
    cmake -S /workspace -B "$build_dir" -G Ninja -DCMAKE_BUILD_TYPE=Debug
}

case "$1" in
    build|test)
        configure
        cmake --build "$build_dir" --parallel 2
        if [[ "$1" == test ]]; then
            ctest --test-dir "$build_dir" --output-on-failure
        fi
        ;;
    clang-tidy)
        configure
        failed=0
        while IFS= read -r -d '' source; do
            status=0
            clang-tidy -p "$build_dir" --quiet "$source" >/tmp/tidy.log 2>&1 || status=$?
            sed -E '/^[0-9]+ warnings? generated\.$/d' /tmp/tidy.log
            if grep -E ': (warning|error): ' /tmp/tidy.log |
                    grep -vE '\[clang-diagnostic-' >/tmp/tidy-findings; then
                failed=1
            fi
            if (( status != 0 )); then
                if (( status != 1 )) || ! grep -q '\[clang-diagnostic-error\]' /tmp/tidy.log; then
                    failed=1
                fi
            fi
        done < <(find /workspace/src -name '*.cpp' -print0)
        exit "$failed"
        ;;
    cppcheck)
        configure
        cppcheck --project="$build_dir/compile_commands.json" --file-filter='/workspace/src/*' \
            --enable=warning,performance,portability --check-level=exhaustive --error-exitcode=1
        ;;
    hardening)
        cmake -S /workspace -B /build/release -G Ninja -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_TESTING=OFF
        cmake --build /build/release --parallel 2
        binary=/build/release/erikslund-mmproxy
        header=$(readelf -h "$binary")
        dynamic=$(readelf -d "$binary")
        segments=$(readelf -lW "$binary")
        stack=$(grep GNU_STACK <<< "$segments" || true)
        symbols=$(nm -D "$binary")
        missing() {
            echo "missing $1 in $binary" >&2
            exit 1
        }
        [[ $header == *DYN* ]] || missing "position independence"
        [[ $dynamic == *FLAGS_1*PIE* ]] || missing "the PIE flag"
        [[ $dynamic == *BIND_NOW* ]] || missing "immediate binding"
        [[ $segments == *GNU_RELRO* ]] || missing "RELRO"
        [[ -n $stack && $stack != *RWE* ]] || missing "a non-executable stack"
        [[ $symbols == *__stack_chk_fail* ]] || missing "the stack protector"
        echo "hardening ok: PIE, full RELRO, non-executable stack, stack protector"
        ;;
    *)
        exit 2
        ;;
esac
