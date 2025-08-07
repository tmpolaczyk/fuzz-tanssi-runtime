Create snapshot of a live network

Install this tool

github.com/tmpolaczyk/snap2zombie/

And the script from `scripts/create_snapshot.py`

```sh
./scripts/create_snapshot.py --alias stagelight
# Will output to snapshots/stagelight-2025-08-08.json
# To set a custom output file:
./scripts/create_snapshot.py --alias stagelight --output stagelight-today.json
```
