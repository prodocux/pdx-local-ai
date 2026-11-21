"""Single runtime pin for the published Kernel and Engine wheels.

pyproject.toml and requirements-ci.txt repeat these strings because setuptools
static metadata cannot import this module. tests/test_version_pin.py fails
when those copies drift.
"""

KERNEL_VERSION = "0.3.0rc13"
ENGINE_VERSION = "0.3.0a13"

KERNEL_WHEEL = "prodocux-0.3.0rc13-py3-none-any.whl"
KERNEL_WHEEL_BYTES = 289336
KERNEL_WHEEL_SHA256 = "900e88664917384d856ab368321cd3b274431aba4acb377c7d3db8c186d4454e"

ENGINE_WHEEL = "pdx_artifact_engine-0.3.0a13-py3-none-any.whl"
ENGINE_WHEEL_BYTES = 240609
ENGINE_WHEEL_SHA256 = "87439f372921cdd42db99778248987d9e5ab3c5fc3512f8ca50be9008b7b9f7e"
