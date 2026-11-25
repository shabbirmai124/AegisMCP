use boa_engine::{Context, JsValue, Source};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[derive(Deserialize)]
struct GuestInput {
    code: String,
    #[serde(default)]
    input: serde_json::Value,
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Serialize)]
struct GuestOutput {
    ok: bool,
    result: serde_json::Value,
    console_logs: Vec<String>,
    error: Option<String>,
}

fn emit_output(out: &GuestOutput) {
    if let Ok(json) = serde_json::to_string(out) {
        println!("{json}");
    }
}

fn js_value_to_json(val: &JsValue, ctx: &mut Context) -> serde_json::Value {
    if val.is_undefined() || val.is_null() {
        return serde_json::Value::Null;
    }
    if let Ok(Some(v)) = val.to_json(ctx) {
        return v;
    }
    serde_json::Value::String(val.display().to_string())
}

fn main() {
    let mut raw = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut raw) {
        emit_output(&GuestOutput {
            ok: false,
            result: serde_json::Value::Null,
            console_logs: Vec::new(),
            error: Some(format!("Failed to read stdin envelope: {err}")),
        });
        return;
    }

    let req: GuestInput = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            emit_output(&GuestOutput {
                ok: false,
                result: serde_json::Value::Null,
                console_logs: Vec::new(),
                error: Some(format!("Invalid JSON input envelope: {err}")),
            });
            return;
        }
    };

    let mut context = Context::default();
    let input_json = serde_json::to_string(&req.input).unwrap_or_else(|_| "null".to_string());
    let tier_json = serde_json::to_string(&req.tier.unwrap_or_else(|| "pure_compute".to_string()))
        .unwrap_or_else(|_| "\"pure_compute\"".to_string());

    let prelude = format!(
        r#"
const input = {input_json};
const __AEGIS_TIER__ = {tier_json};
const __logs = [];
const console = {{
  log: (...args) => __logs.push(args.map(v => typeof v === 'object' ? JSON.stringify(v) : String(v)).join(' ')),
  warn: (...args) => __logs.push('WARN: ' + args.map(v => typeof v === 'object' ? JSON.stringify(v) : String(v)).join(' ')),
  error: (...args) => __logs.push('ERROR: ' + args.map(v => typeof v === 'object' ? JSON.stringify(v) : String(v)).join(' '))
}};
"#
    );

    if let Err(err) = context.eval(Source::from_bytes(prelude.as_bytes())) {
        emit_output(&GuestOutput {
            ok: false,
            result: serde_json::Value::Null,
            console_logs: Vec::new(),
            error: Some(format!("Guest prelude initialization failed: {err}")),
        });
        return;
    }

    let eval_res = context.eval(Source::from_bytes(req.code.as_bytes()));
    let logs_json = context
        .eval(Source::from_bytes(b"JSON.stringify(__logs)"))
        .ok()
        .and_then(|v| v.to_string(&mut context).ok())
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_else(|| "[]".to_string());
    let console_logs: Vec<String> = serde_json::from_str(&logs_json).unwrap_or_default();

    match eval_res {
        Ok(val) => {
            let result = js_value_to_json(&val, &mut context);
            emit_output(&GuestOutput {
                ok: true,
                result,
                console_logs,
                error: None,
            });
        }
        Err(err) => {
            emit_output(&GuestOutput {
                ok: false,
                result: serde_json::Value::Null,
                console_logs,
                error: Some(err.to_string()),
            });
        }
    }
}
