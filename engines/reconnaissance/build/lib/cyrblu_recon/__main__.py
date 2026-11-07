import argparse
import json
import logging
from pathlib import Path

import uvicorn

from .app import create_app
from .config.settings import Settings, initialize
from .intelligence.signing import verify


def main():
    parser = argparse.ArgumentParser(description="Independent Cyrblu reconnaissance service")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--config-dir", type=Path, default=Path(".recon-config"))
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8090)
    check = commands.add_parser("verify")
    check.add_argument("package", type=Path)
    check.add_argument("--trusted-key", type=Path, required=True)
    options = parser.parse_args()
    if options.command == "init":
        initialize(options.config_dir)
        print(f"Independent credentials and signing keys initialized in {options.config_dir}")
    elif options.command == "verify":
        package = verify(json.loads(options.package.read_text()), options.trusted_key)
        print(f"Verified reconnaissance package {package.payload.assessment_id} ({package.payload.execution_status})")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
        uvicorn.run(create_app(Settings.environment()), host="127.0.0.1", port=options.port, workers=1)


if __name__ == "__main__":
    main()
