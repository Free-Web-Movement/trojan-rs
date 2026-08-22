# Usage

```
trojan-rs - An unidentifiable mechanism that helps you bypass GFW

Usage: trojan-rs [OPTIONS] [CONFIG]

Arguments:
  [CONFIG]  

Options:
  -c, --config <CONFIG>  
  -l, --log <LOG>        
  -k, --keylog <KEYLOG>  
  -t, --test             
  -v, --build-info       
  -h, --help             Print help
  -V, --version          Print version
```

The default value for CONFIG is `config.json` in the working directory.

On Linux and other UNIX-like systems, the behavior of the handlers for the following signals are overridden:

- `SIGHUP`: Upon receiving `SIGHUP`, trojan will stop the service, reload the config, and restart the service. All existing connections are dropped. As a side effect, if trojan is left in the background of a shell, it will not exit when the shell exits.
- `SIGUSR1`: Certificate hot-reloading is not supported yet; trojan-rs logs a warning and keeps running.

Make sure your [config file](config) is valid. Configuring trojan is not trivial: there are several ideas you need to understand and several pitfalls you might fall into. Unless you are an expert, you shouldn't configure a trojan server all by yourself.

Here, we will present a list of things you should do before you start a trojan server:

- setup an `HTTP` server and make it useful in some sense (to deceive `GFW`).
- register a domain name for your server.
- Apply for or self-sign (**NOT RECOMMENDED**) an `SSL` certificate.
- Correctly write the [config file](config).

[Shadowsocks SIP003](https://shadowsocks.org/en/spec/Plugin.html) is supported by trojan, but it is added as an experimental feature and is not standard at all, so it will not be documented here.

[Homepage](.) | [Prev Page](build)
