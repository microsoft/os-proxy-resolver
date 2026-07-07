/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Not a shipped example — used to verify that repeated PAC evaluations do
//! not leak QuickJS values or C strings (run under `leaks --atExit`).
use pac_eval::PacEngine;

fn main() {
    let mut engine = PacEngine::new().expect("engine");
    engine
        .load(
            r#"
            function FindProxyForURL(url, host) {
                alert("checking", host);
                if (isInNet(myIpAddress(), "10.0.0.0", "255.0.0.0")) return "PROXY p:1";
                return shExpMatch(host, "*.example.com") ? "PROXY q:2; DIRECT" : "DIRECT";
            }
            "#,
        )
        .expect("load");
    engine.set_log_sink(|_| {});
    engine.set_my_ip(Some("10.1.2.3".parse().expect("ip")));
    for i in 0..20000 {
        let host = format!("h{i}.example.com");
        let _ = engine
            .find_proxy(&format!("http://{host}/x"), &host)
            .expect("find_proxy");
    }
    // Also exercise error paths repeatedly.
    for _ in 0..2000 {
        let _ = engine.find_proxy("http://x/", "x");
        let _ = PacEngine::eval_once(
            "function FindProxyForURL(u,h){ throw new Error('e'); }",
            "http://x/",
            "x",
        );
        let _ = PacEngine::eval_once("syntax error(", "http://x/", "x");
    }
    println!("done");
}
