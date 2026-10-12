import io

# Fix 1: td_driver.cpp - remove the misplaced teardown from inside if/else,
# put it after the whole notify block.
p = 'td_driver.cpp'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()
old = """        /* F12 teardown: sweep VBox hooks and only then free the command page. */
        TdVbxHookRemoveAll();
        TdVbxCmdFini();
        else
        {"""
assert s.count(old) == 1
s = s.replace(old, """        else
        {""")
# now insert after the outer if-block closes: anchor = the error-log else block end
old2 = """        else
        {
            HYPERPLATFORM_LOG_ERROR(
                "[td] Process notify callback removal FAILED: 0x%08X", notify_st);
        }
    }
"""
assert s.count(old2) == 1
s = s.replace(old2, """        else
        {
            HYPERPLATFORM_LOG_ERROR(
                "[td] Process notify callback removal FAILED: 0x%08X", notify_st);
        }
    }

    /* F12 teardown: sweep VBox hooks and free the command page only after
       the notify callbacks are gone. */
    TdVbxHookRemoveAll();
    TdVbxCmdFini();
""")
io.open(p, 'w', encoding='utf-8', errors='surrogateescape', newline='').write(s)
print("driver unload fixed")

# Fix 2: td_notify.cpp - restore the original cleanup call
p = 'td_notify.cpp'
s = io.open(p, encoding='utf-8', errors='surrogateescape').read()
n = s.count("TdMemoryBreakpointCleanupProcessVBoxAware((UINT64)ProcessId);")
assert n == 2
s = s.replace("TdMemoryBreakpointCleanupProcessVBoxAware((UINT64)ProcessId);",
              "TdMemoryBreakpointCleanupProcess((UINT64)ProcessId);")
io.open(p, 'w', encoding='utf-8', errors='surrogateescape', newline='').write(s)
print("notify calls fixed")
