# luajit.io

## Introduction

**Pure Lua IO framework, with C efficiency due to its simple but powerful design, and, of course, thanks to luajit, the perfect JIT engine. The HTTP Server is out-of-the-box, which simulates the functionalities and performance of nginx and ngx_lua. Moreover, it could be used to develop generic TCP/UDP server.**

Why reinvent the wheel? Well, the nginx and ngx_lua is renowned at effciency and extensible, but they are written in C language, so you need to be as smart as the authors to contribute codes. What if the core is written in pure lua language, but without any effciency tradeoff? Then not only the web apps are extensible, but also the server core is extensible at ease by any levels of developers!

The Luajit is a perfect JIT engine to improve lua performance, so with dedicated and luajit-oriented design, the luajit.io would reassemble the advantages of nginx and ngx_lua, but provides extra benefit: simple and extensible at the core.

**See the http://luajit.io for demo.**

## Status

This library is considered experimental and still under active development.

And there is still big room to improve the performance, by increasing the jit compiled ratio, which is really a tough job.

Welcome to join and help!

## QuickStart

Just like the API compatibility, the luajit.io configuration simulates the nginx.conf, so most directives are copied from there.
See conf/httpd.lua for example.

Copy the example into new file, e.g. conf/myhttpd.lua, and adjust the content according to your need.

Then just run it:

``` shell
luajit conf/myhttpd.lua
```
