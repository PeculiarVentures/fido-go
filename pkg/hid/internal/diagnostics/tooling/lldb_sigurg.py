"""Optional LLDB driver for strict actual-IOKit-entry HID diagnostics.

Use a diagnostic binary compiled with -tags=hid_diagnostics,integration:
  lldb --batch \
    -o 'command script import /absolute/path/lldb_sigurg.py' \
    -o 'hid-diagnostics-run /absolute/path/hid.test /absolute/path/report.json'

The target entrypoint is TestHIDDiagnosticsHardware. It requires authorized
read-only hardware access. No debugger/system security settings are weakened.
The companion report.json.lldb.json describes debugger evidence; the Go JSON
report remains the source of scenario outcomes. Missing hits are INCONCLUSIVE.
The optional --timeout sets Go's test timeout; it is not an independent LLDB
wall-clock watchdog and cannot bound a stalled debugger expression or launch.
"""

import json
import os
import shlex
import time

import lldb

_state = None


def _evaluate(frame, expression):
    options = lldb.SBExpressionOptions()
    options.SetIgnoreBreakpoints(True)
    options.SetTryAllThreads(False)
    options.SetUnwindOnError(True)
    options.SetTimeoutInMicroSeconds(2_000_000)
    value = frame.EvaluateExpression(expression, options)
    if value.GetError().Fail():
        raise RuntimeError(value.GetError().GetCString() or "native helper evaluation failed")
    return value.GetValueAsUnsigned()


def _native_entry(frame, _location, _dictionary):
    """Runs only at the actual IOHIDDeviceSetReport symbol, on its live thread."""
    global _state
    if _state is None:
        return False
    _state["api_breakpoint_hits"] += 1
    try:
        generation = _evaluate(
            frame, "(unsigned long long)hid_diagnostics_current_generation()"
        )
        if not generation:
            return False
        _state["armed_writer_hits"] += 1
        code = _evaluate(
            frame, "(int)hid_diagnostics_native_entry(%dULL)" % generation
        )
        if code:
            _state["errors"].append("native entry helper returned errno %d" % code)
        else:
            _state["successful_injections"] += 1
    except Exception as error:
        # An unavailable expression/helper is missing evidence, never a pass.
        _state["errors"].append(str(error))
    # Preserve normal target execution after recording evidence. SIGURG remains
    # pass=true/stop=false; neither the callback nor the driver suppresses it.
    return False


def _write_evidence(path):
    encoded = json.dumps(_state, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(encoded)


def run(debugger, command, result, _dictionary):
    """hid-diagnostics-run BINARY ABSOLUTE_REPORT_PATH [--timeout=90]"""
    global _state
    arguments = shlex.split(command)
    if len(arguments) not in (2, 3):
        result.SetError("usage: hid-diagnostics-run BINARY ABSOLUTE_REPORT_PATH [--timeout=90]")
        return
    binary, report_path = arguments[:2]
    if not os.path.isabs(binary) or not os.path.isabs(report_path):
        result.SetError("binary and JSON report paths must be absolute")
        return
    timeout = 90
    if len(arguments) == 3:
        if not arguments[2].startswith("--timeout="):
            result.SetError("only --timeout=SECONDS is accepted")
            return
        timeout = int(arguments[2].split("=", 1)[1])
        if timeout < 1 or timeout > 300:
            result.SetError("timeout must be between 1 and 300 seconds")
            return
    _state = {
        "schema_version": 1,
        "status": "INCONCLUSIVE",
        "evidence": "actual-IOKit-entry",
        "sigurg_pass": True,
        "sigurg_stop": False,
        "api_breakpoint_hits": 0,
        "armed_writer_hits": 0,
        "successful_injections": 0,
        "errors": [],
    }
    started = time.monotonic()
    process = None
    try:
        # The report path is this invocation's declared output. Never accept
        # a prior run's success if launch or test execution fails to rewrite it.
        try:
            os.unlink(report_path)
        except FileNotFoundError:
            pass
        debugger.SetAsync(False)
        target = debugger.CreateTarget(binary)
        if not target.IsValid():
            raise RuntimeError("LLDB could not create the diagnostic target")
        breakpoint = target.BreakpointCreateByName("IOHIDDeviceSetReport")
        breakpoint.SetScriptCallbackFunction(__name__ + "._native_entry")
        launch = lldb.SBLaunchInfo([
            "-test.run=^TestHIDDiagnosticsHardware$", "-test.v",
            "-test.timeout=%ds" % timeout,
        ])
        launch.SetEnvironmentEntries([
            "FIDO_HID_DIAGNOSTICS=1",
            "FIDO_HID_DIAGNOSTICS_STRICT=1",
            "FIDO_HID_DIAGNOSTICS_REPORT=" + report_path,
        ], True)
        # Stop once at process entry so the handler policy is configured before
        # any Go or native diagnostic code runs.
        launch.SetLaunchFlags(launch.GetLaunchFlags() | lldb.eLaunchFlagStopAtEntry)
        error = lldb.SBError()
        process = target.Launch(launch, error)
        if error.Fail() or not process.IsValid():
            raise RuntimeError(error.GetCString() or "LLDB launch unavailable")
        handled = lldb.SBCommandReturnObject()
        debugger.GetCommandInterpreter().HandleCommand(
            "process handle SIGURG -s false -n false -p true", handled
        )
        if not handled.Succeeded():
            raise RuntimeError("LLDB could not preserve SIGURG pass-through handling")
        while process.GetState() == lldb.eStateStopped:
            process.Continue()
            if process.GetState() == lldb.eStateStopped:
                raise RuntimeError("target stopped outside the non-stopping native entry callback")
        if process.GetState() != lldb.eStateExited:
            raise RuntimeError("target did not reach a normal process exit")
        _state["target_exit_status"] = process.GetExitStatus()
        try:
            with open(report_path, encoding="utf-8") as source:
                report = json.load(source)
            strict = next((item for item in report.get("results", [])
                           if item.get("scenario_id") == "hardware.strict-iokit-entry"), None)
        except (OSError, ValueError) as error:
            strict = None
            _state["errors"].append("Go report unavailable: " + str(error))
        if strict:
            _state["strict_scenario_status"] = strict.get("status", "INCONCLUSIVE")
            if strict.get("status") == "FAIL":
                _state["status"] = "FAIL"
            elif (strict.get("status") == "PASS"
                  and strict.get("facts", {}).get("all_native_entries_confirmed")
                  and _state["successful_injections"] > 0
                  and not _state["errors"]
                  and process.GetExitStatus() == 0):
                _state["status"] = "PASS"
        if not _state["successful_injections"]:
            _state["errors"].append("no armed actual-IOKit-entry injection was confirmed")
    except Exception as error:
        _state["errors"].append(str(error))
        if process and process.IsValid() and process.GetState() != lldb.eStateExited:
            # Stop debugger-owned execution before releasing its target. This is
            # diagnostic-only read-only traffic; no runtime command is replayed.
            process.Kill()
    finally:
        _state["duration_ns"] = int((time.monotonic() - started) * 1_000_000_000)
        try:
            _write_evidence(report_path + ".lldb.json")
        except OSError as error:
            result.SetError("could not write LLDB evidence: " + str(error))
            return
        result.AppendMessage("HID strict IOKit-entry diagnostic: " + _state["status"])
        if _state["status"] != "PASS":
            result.SetError("strict entry evidence was not sufficient; see companion LLDB JSON")


def __lldb_init_module(debugger, _dictionary):
    debugger.HandleCommand(
        "command script add -f " + __name__ + ".run hid-diagnostics-run"
    )
