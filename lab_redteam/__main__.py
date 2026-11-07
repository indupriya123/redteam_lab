import argparse

import uvicorn


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the loopback-only lab assessment dashboard")
    parser.add_argument("--port", type=int, default=8765, help="Dashboard port (default: 8765)")
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("Choose an unprivileged dashboard port between 1024 and 65535")
    uvicorn.run("lab_redteam.app:create_app", factory=True, host="127.0.0.1", port=args.port, workers=1)


if __name__ == "__main__":
    main()
