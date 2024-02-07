# exports.exe - Anti API-hashing tool

This program dumps every exports from given PE files using multi-threading, and builds a hashtable from a user supplied hash function. This is useful when reverse-engineering programs (generally malwares) that use an import-by-hash anti-analysis feature.




## Features

- multi-threading
- customized hash function via Python
- JSON format output
- lazy format output
- process directories recursively
- no dependency, except Python





## License

[MIT](https://choosealicense.com/licenses/mit/)
