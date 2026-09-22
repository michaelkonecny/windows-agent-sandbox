import sys

if len(sys.argv) >= 2 and sys.argv[1] == "_elevate":
    from sbx.elevation import execute

    execute(sys.argv[2], sys.argv[3])
elif len(sys.argv) >= 2 and sys.argv[1] == "_proxy":
    from sbx.proxy import run_proxy_main

    run_proxy_main()
elif len(sys.argv) >= 6 and sys.argv[1] == "_run":
    from sbx.process import execute_runner

    port = None if sys.argv[5] == "-" else int(sys.argv[5])
    sys.exit(execute_runner(sys.argv[2], sys.argv[3], sys.argv[4], port))
else:
    from sbx.cli import main

    main()
