import sys

if len(sys.argv) >= 2 and sys.argv[1] == "_elevate":
    from sbx.elevation import execute

    execute(sys.argv[2], sys.argv[3])
elif len(sys.argv) >= 2 and sys.argv[1] == "_proxy":
    from sbx.proxy import run_proxy_main

    run_proxy_main()
elif len(sys.argv) >= 8 and sys.argv[1] == "_run":
    from sbx.process import execute_runner

    name, sid, shell, port, nonce, host_sid = sys.argv[2:8]
    port = None if port == "-" else int(port)
    sys.exit(execute_runner(name, sid, shell, port, nonce, host_sid))
else:
    from sbx.cli import main

    main()
