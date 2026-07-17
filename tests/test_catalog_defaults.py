from s1engine.catalog import Catalog, Query


def _q(pq):
    return Query(id="q1", title="t", pq=pq)


def test_required_var_without_default_is_required():
    q = _q("serverHost=x | filter name contains:anycase('{{app_name}}')")
    assert q.required_vars() == ["app_name"]


def test_defaulted_var_is_not_required():
    q = _q("serverHost='{{src_zia|zia}}' | filter x=1")
    # A defaulted variable never gates skipping.
    assert q.required_vars() == []


def test_render_prefers_value_then_default_then_raises():
    q = _q("serverHost='{{src_zia|zia}}' name='{{app_name}}'")
    # Default used when the var is unset.
    out = q.render({"app_name": "anydesk"})
    assert "serverHost='zia'" in out and "name='anydesk'" in out
    # Provided value overrides the default.
    out2 = q.render({"app_name": "anydesk", "src_zia": "zscaler_web"})
    assert "serverHost='zscaler_web'" in out2
    # Empty value falls back to the default, not the empty string.
    out3 = q.render({"app_name": "x", "src_zia": "  "})
    assert "serverHost='zia'" in out3


def test_missing_required_var_raises():
    q = _q("name='{{app_name}}'")
    try:
        q.render({})
    except KeyError:
        return
    raise AssertionError("expected KeyError for missing required var")


def test_catalog_template_vars_classifies_defaults():
    cat = Catalog(name="c", queries=[
        _q("serverHost='{{src_zia|zia}}' u='{{username}}' a='{{app_name}}'"),
    ])
    tv = cat.template_vars()
    assert tv["src_zia"] == "zia"      # defaulted (overridable)
    assert tv["username"] == ""        # required (gates skipping)
    assert tv["app_name"] == ""
