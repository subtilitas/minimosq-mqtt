# minimosq

A small MQTT 3.1.1 broker as a header-only C++17 template library for
embedded use: fully static after startup, no exceptions, no RTTI, and no
dependencies beyond a handful of freestanding C++ headers.

Work in progress — the full documentation lands with the final commit.

## Building the tests

```sh
cmake -B build -DMINIMOSQ_WERROR=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## License

MIT — see [LICENSE](LICENSE).
