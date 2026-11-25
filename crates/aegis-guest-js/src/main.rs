use boa_engine::object::ObjectInitializer;
use boa_engine::object::builtins::JsArray;
use boa_engine::property::Attribute;
use boa_engine::{Context, JsArgs, JsNativeError, JsResult, JsString, JsValue, NativeFunction, Source};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

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
    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, out);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
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

fn aegis_fs_read_file(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let path = args
        .get_or_undefined(0)
        .to_string(ctx)?
        .to_std_string_escaped();
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(JsValue::from(JsString::from(content))),
        Err(err) => Err(JsNativeError::error()
            .with_message(format!("CapabilityDenied: readFile('{path}') failed: {err}"))
            .into()),
    }
}

fn aegis_fs_write_file(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let path = args
        .get_or_undefined(0)
        .to_string(ctx)?
        .to_std_string_escaped();
    let content = args
        .get_or_undefined(1)
        .to_string(ctx)?
        .to_std_string_escaped();
    match std::fs::write(&path, content.as_bytes()) {
        Ok(()) => Ok(JsValue::from(true)),
        Err(err) => Err(JsNativeError::error()
            .with_message(format!("CapabilityDenied: writeFile('{path}') failed: {err}"))
            .into()),
    }
}

fn aegis_fs_read_dir(_this: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    let path = args
        .get_or_undefined(0)
        .to_string(ctx)?
        .to_std_string_escaped();
    match std::fs::read_dir(&path) {
        Ok(entries) => {
            let mut names = Vec::new();
            for entry in entries {
                match entry {
                    Ok(e) => names.push(e.file_name().to_string_lossy().into_owned()),
                    Err(err) => {
                        return Err(JsNativeError::error()
                            .with_message(format!(
                                "CapabilityDenied: readDir('{path}') entry error: {err}"
                            ))
                            .into());
                    }
                }
            }
            names.sort();
            let js_vals: Vec<JsValue> = names
                .into_iter()
                .map(|n| JsValue::from(JsString::from(n)))
                .collect();
            let arr = JsArray::from_iter(js_vals, ctx);
            Ok(arr.into())
        }
        Err(err) => Err(JsNativeError::error()
            .with_message(format!("CapabilityDenied: readDir('{path}') failed: {err}"))
            .into()),
    }
}

fn register_aegis_fs(ctx: &mut Context) -> JsResult<()> {
    let aegis_fs = ObjectInitializer::new(ctx)
        .function(
            NativeFunction::from_fn_ptr(aegis_fs_read_file),
            JsString::from("readFile"),
            1,
        )
        .function(
            NativeFunction::from_fn_ptr(aegis_fs_write_file),
            JsString::from("writeFile"),
            2,
        )
        .function(
            NativeFunction::from_fn_ptr(aegis_fs_read_dir),
            JsString::from("readDir"),
            1,
        )
        .build();

    ctx.register_global_property(JsString::from("aegisFS"), aegis_fs, Attribute::READONLY)?;
    Ok(())
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
    if let Err(err) = register_aegis_fs(&mut context) {
        emit_output(&GuestOutput {
            ok: false,
            result: serde_json::Value::Null,
            console_logs: Vec::new(),
            error: Some(format!("Failed to register aegisFS bridge: {err}")),
        });
        return;
    }

    let input_json = serde_json::to_string(&req.input).unwrap_or_else(|_| "null".to_string());
    let tier_json = serde_json::to_string(&req.tier.unwrap_or_else(|| "pure_compute".to_string()))
        .unwrap_or_else(|_| "\"pure_compute\"".to_string());

    let prelude = format!(
        r#"
const INPUT = {input_json};
const input = INPUT;
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
