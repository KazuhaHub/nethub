# Native W5 package preparation

The unsigned 0.0.17 package was built on the native FreeBSD appliance from
`77ddab2` in 457.032 seconds with the accepted 1 GiB allocation. The package,
product and model versions agree; all 46 tracked packaged source files matched
their committed hashes. The exported package SHA256 is
`450dc403d8a326ba8ab8d493b9b144a51572db92d698b59569108ec87893d0a5`.

Independent post-restore checks confirmed the original 0.0.6 package, byte-identical
native configuration, operator stop, stopped frpc and usable configd. The candidate
was not installed. This proves package preparation and baseline restoration;
installed circuit-breaker and combined public W5 acceptance remain open.
