# BIP340 conversion

```sh
python3 -c "import csv, json; print(json.dumps([i for i in csv.DictReader(open('bip340.csv'), delimiter=',')]))" > bip340.json
```
