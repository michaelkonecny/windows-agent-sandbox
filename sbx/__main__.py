import sys

if len(sys.argv) >= 2 and sys.argv[1] == "_elevate":
    from sbx.elevation import execute

    execute(sys.argv[2], sys.argv[3])
else:
    try:
        from sbx.cli import main

        main()
    except ImportError:
        print("CLI not yet implemented", file=sys.stderr)
        sys.exit(1)
