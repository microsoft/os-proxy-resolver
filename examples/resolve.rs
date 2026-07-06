/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Resolve URLs against the live OS proxy configuration.
//!
//! ```text
//! cargo run --example resolve -- <url> [<url>...]
//! cargo run --example resolve -- --watch     # print config changes as they happen
//! ```

use os_proxy_resolver::ProxyResolver;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: resolve <url> [<url>...] | resolve --watch");
        std::process::exit(2);
    }
    let resolver = ProxyResolver::new();

    if args[0] == "--watch" {
        println!(
            "watching for OS proxy config changes (generation {})... Ctrl-C to stop",
            resolver.config_generation()
        );
        let r = resolver.clone();
        let _sub = resolver.on_change(move || {
            // Cheap and non-blocking, per the on_change contract.
            println!("change! generation is now {}", r.config_generation());
        });
        loop {
            std::thread::park();
        }
    }

    for raw in &args {
        match url::Url::parse(raw) {
            Ok(url) => match resolver.resolve_proxy(&url) {
                Ok(list) => {
                    let rendered: Vec<String> = list.iter().map(|p| p.to_string()).collect();
                    println!("{raw} -> {}", rendered.join("; "));
                }
                Err(e) => eprintln!("{raw} -> error: {e}"),
            },
            Err(e) => eprintln!("{raw} -> invalid URL: {e}"),
        }
    }
}
