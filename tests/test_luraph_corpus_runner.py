from tools.run_luraph_v147_corpus import _quality_error, _quality_metrics


def _pipeline(**overrides):
    pipeline = {
        "decompiler": {
            "compile_checked": True,
            "fallback_instructions": 0,
        },
        "payload_executed": False,
        "final_payload_executed": False,
    }
    pipeline.update(overrides)
    return pipeline


def test_quality_metrics_accept_fully_devirtualized_safe_output():
    quality = _quality_metrics(
        _pipeline(),
        {"1": {"unknown_ifs": 0}, "2": {"unknown_ifs": 0}},
    )

    assert quality == {
        "compile_checked": True,
        "fallback_instructions": 0,
        "unknown_ifs": 0,
        "payload_executed": False,
        "final_payload_executed": False,
    }
    assert _quality_error(quality) is None


def test_quality_gate_rejects_fallbacks_and_unknown_conditionals():
    pipeline = _pipeline()
    pipeline["decompiler"]["fallback_instructions"] = 3
    quality = _quality_metrics(pipeline, {"7": {"unknown_ifs": 2}})

    assert quality["fallback_instructions"] == 3
    assert quality["unknown_ifs"] == 2
    assert _quality_error(quality) == "semantic fallback instructions remain"


def test_quality_gate_requires_explicit_payload_safety_flags():
    pipeline = _pipeline()
    del pipeline["final_payload_executed"]
    quality = _quality_metrics(pipeline, {})

    assert _quality_error(quality) == "final payload execution safety flag is missing or true"


def test_quality_metrics_reject_malformed_integer_fields():
    pipeline = _pipeline()
    pipeline["decompiler"]["fallback_instructions"] = True
    quality = _quality_metrics(pipeline, {"9": {"unknown_ifs": "0"}})

    assert quality["fallback_instructions"] == -1
    assert quality["unknown_ifs"] == -1


def test_quality_metrics_reject_non_object_decompiler_metadata():
    quality = _quality_metrics(_pipeline(decompiler=[]), {})

    assert quality["compile_checked"] is False
    assert quality["fallback_instructions"] == -1


def test_quality_metrics_prefers_emitted_residual_condition_count():
    pipeline = _pipeline()
    pipeline["decompiler"]["unresolved_dispatcher_conditionals"] = 0
    quality = _quality_metrics(pipeline, {"7": {"unknown_ifs": 9}})

    assert quality["unknown_ifs"] == 0
