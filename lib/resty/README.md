Normally, lua-resty-* contains a Makefile, so you could just invoke `make install`:

``` shell
make LUA_LIB_DIR=<path>/luajit.io/lib install
```

Or, just copy `lib/resty/*`:

``` shell
cp -a <lua-resty-*>/lib/resty/* <path>/luajit.io/lib/resty/
```
