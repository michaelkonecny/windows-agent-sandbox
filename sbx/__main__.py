import sys

if len(sys.argv) >= 2 and sys.argv[1] == "_elevate":
    from sbx.elevation import execute

    execute(sys.argv[2], sys.argv[3])
elif len(sys.argv) >= 2 and sys.argv[1] == "_proxy":
    from sbx.proxy import run_proxy_main

    run_proxy_main()
elif len(sys.argv) >= 5 and sys.argv[1] == "_run":
    from sbx.process import DEFAULT_SIZE, execute_runner

    # Terminal size is optional so the runner stays launchable by hand.
    cols = int(sys.argv[5]) if len(sys.argv) >= 6 else DEFAULT_SIZE[0]
    rows = int(sys.argv[6]) if len(sys.argv) >= 7 else DEFAULT_SIZE[1]
    execute_runner(sys.argv[2], sys.argv[3], sys.argv[4], cols, rows)
else:
    from sbx.cli import main

    main()
