# test_provision.py -- regression suite for the host-side provisioner (host/provision.py).
#
# provision.py is pure, hardware-free Python for everything security-relevant, yet it enforces
# several invariants that a silent regression could turn into an on-device lockout or -- on an
# ARMED board -- a self-wipe (see the docstrings in provision.py and docs/SPEC.md sections 4/9/10).
# These tests lock those invariants: partition-offset resolution, the fail-safe arm pair rejection,
# password/KDF bounds, the guardcfg NVS size floor, and the exactly-one-otadata-seed manifest rule.
#
# Standard library + pytest only. No hardware and no NVS generator are required: the two
# generate_nvs_bin cases exercise the size guards, which fire BEFORE the generator is ever invoked,
# so a throwaway stub file is enough to satisfy the discovery step.

import argparse
import glob
import hashlib
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
HOST_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(HOST_DIR)
PARTS_DIR = os.path.join(REPO_ROOT, "firmware", "partitions")

sys.path.insert(0, HOST_DIR)
import provision  # noqa: E402


CSV_FILES = sorted(glob.glob(os.path.join(PARTS_DIR, "*.csv")))


def _args(**overrides):
    """Parse a real CLI arg vector (so defaults/types match production) with optional overrides."""
    argv = ["--partitions", os.path.join(PARTS_DIR, "suicide_4MB.csv")]
    for key, val in overrides.items():
        argv.extend(["--" + key.replace("_", "-"), str(val)])
    return provision.build_arg_parser().parse_args(argv)


# ----------------------------------------------------------------------------------------------
# parse_partitions_csv / require_partition -- offsets are READ, never hardcoded
# ----------------------------------------------------------------------------------------------

def test_partition_csvs_present():
    # Guard: if the shipped tables ever move, the parametrized tests below would silently run
    # with zero cases and still go green. Fail loudly instead.
    assert CSV_FILES, "no partition CSVs found under firmware/partitions/"


@pytest.mark.parametrize("csv_path", CSV_FILES, ids=[os.path.basename(p) for p in CSV_FILES])
def test_real_csv_resolves_gate_partitions(csv_path):
    parts = provision.parse_partitions_csv(csv_path)
    guardcfg = provision.require_partition(parts, provision.GUARDCFG_PART)
    otadata = provision.require_partition(parts, provision.OTADATA_PART)
    # guardcfg is the NVS partition the host + firmware both key off; it must be read/write-sized.
    assert guardcfg["subtype"] == "nvs"
    assert guardcfg["offset"] is not None and guardcfg["size"] is not None
    assert guardcfg["size"] >= 0x3000  # read/write NVS floor (SPEC 3.1 / generate_nvs_bin)
    # Marauder enlarges nvs, pushing otadata to 0xE000 (not the stock 0xD000) -- lock that fact.
    assert otadata["subtype"] == "ota"
    assert otadata["offset"] == 0xE000


def test_parse_specific_offsets_4mb():
    parts = provision.parse_partitions_csv(os.path.join(PARTS_DIR, "suicide_4MB.csv"))
    assert parts["guardcfg"]["offset"] == 0x1F0000
    assert parts["guardcfg"]["size"] == 0x3000
    assert parts["otadata"]["offset"] == 0xE000
    assert parts["app0"]["offset"] == 0x10000


def test_parse_auto_offsets_and_trailing_comma(tmp_path):
    # Blank offsets must be resolved from the running cursor (apps 64K-aligned, data 4K-aligned),
    # and the trailing comma on every row (empty Flags column) must be tolerated.
    csv_text = (
        "# Name, Type, SubType, Offset, Size, Flags\n"
        "nvs,      data, nvs,   0x9000, 0x5000,\n"
        "otadata,  data, ota,         , 0x2000,\n"
        "app0,     app,  ota_0,       , 0x1E0000,\n"
        "guardcfg, data, nvs,         , 0x3000,\n"
    )
    p = tmp_path / "auto.csv"
    p.write_text(csv_text, encoding="utf-8")
    parts = provision.parse_partitions_csv(str(p))
    assert parts["otadata"]["offset"] == 0xE000     # follows nvs (0x9000 + 0x5000), 4K aligned
    assert parts["app0"]["offset"] == 0x10000       # app aligned up to 64K
    assert parts["guardcfg"]["offset"] == 0x1F0000  # follows app0 (0x10000 + 0x1E0000)


def test_parse_missing_file():
    with pytest.raises(provision.ProvisionError):
        provision.parse_partitions_csv(os.path.join(PARTS_DIR, "does_not_exist.csv"))


def test_require_partition_missing():
    parts = provision.parse_partitions_csv(CSV_FILES[0])
    with pytest.raises(provision.ProvisionError):
        provision.require_partition(parts, "no_such_partition")


def test_parse_size_token():
    assert provision._parse_size_token("0x1F0000") == 0x1F0000
    assert provision._parse_size_token("8192") == 8192
    assert provision._parse_size_token("8K") == 8 * 1024
    assert provision._parse_size_token("1M") == 1024 * 1024
    assert provision._parse_size_token("") is None
    assert provision._parse_size_token(None) is None
    with pytest.raises(provision.ProvisionError):
        provision._parse_size_token("not-a-number")


# ----------------------------------------------------------------------------------------------
# validate_password -- every rejection mirrors a firmware-side normalization (parity guard)
# ----------------------------------------------------------------------------------------------

def test_validate_password_accepts_normal():
    assert provision.validate_password(bytearray(b"correct horse battery")) is None


def test_validate_password_accepts_max_len():
    assert provision.validate_password(bytearray(b"a" * provision.SUICIDE_PW_MAX_BYTES)) is None


def test_validate_password_rejects_empty():
    with pytest.raises(provision.ProvisionError):
        provision.validate_password(bytearray(b""))


def test_validate_password_rejects_too_long():
    with pytest.raises(provision.ProvisionError):
        provision.validate_password(bytearray(b"a" * (provision.SUICIDE_PW_MAX_BYTES + 1)))


@pytest.mark.parametrize("pw", [b" leading", b"trailing ", b"\ttab", b"tab\t"])
def test_validate_password_rejects_surrounding_ws(pw):
    with pytest.raises(provision.ProvisionError):
        provision.validate_password(bytearray(pw))


@pytest.mark.parametrize("pw", [b"unlock secret", b"UNLOCK secret", b"unlock\tsecret"])
def test_validate_password_rejects_unlock_prefix(pw):
    with pytest.raises(provision.ProvisionError):
        provision.validate_password(bytearray(pw))


# ----------------------------------------------------------------------------------------------
# derive_pwhash -- must match hashlib exactly and clamp kdf_iter to the device's NVS u32 range
# ----------------------------------------------------------------------------------------------

def test_derive_pwhash_matches_hashlib():
    salt = b"\x00" * provision.SALT_LEN
    got = provision.derive_pwhash(bytearray(b"passphrase"), salt, 1000, provision.KDF_DKLEN)
    exp = hashlib.pbkdf2_hmac("sha256", b"passphrase", salt, 1000, provision.KDF_DKLEN)
    assert got == exp
    assert len(got) == provision.KDF_DKLEN


@pytest.mark.parametrize("iters", [0, 0x100000000])
def test_derive_pwhash_rejects_out_of_range_iter(iters):
    with pytest.raises(provision.ProvisionError):
        provision.derive_pwhash(bytearray(b"x"), b"\x00" * provision.SALT_LEN, iters)


# ----------------------------------------------------------------------------------------------
# validate_args -- fail-safe arm pairs, max_att>=1 clamp, kdf_iter bounds
# ----------------------------------------------------------------------------------------------

def test_validate_args_defaults_ok():
    provision.validate_args(_args())


@pytest.mark.parametrize("lvl,pull", [(1, 2), (0, 1)])
def test_validate_args_accepts_failsafe_pairs(lvl, pull):
    # level=1+pulldown and level=0+pullup idle the pin NOT-ARMED, so a cut wire reads DISARMED.
    provision.validate_args(_args(arm_level=lvl, arm_pull=pull))


@pytest.mark.parametrize("lvl,pull", [(1, 1), (0, 2)])
def test_validate_args_rejects_nonfailsafe_pairs(lvl, pull):
    # level=1+pullup and level=0+pulldown idle the pin toward ARMED -> a cut wire defeats deadman.
    with pytest.raises(provision.ProvisionError):
        provision.validate_args(_args(arm_level=lvl, arm_pull=pull))


def test_validate_args_rejects_max_att_zero():
    with pytest.raises(provision.ProvisionError):
        provision.validate_args(_args(max_att=0))


def test_validate_args_accepts_max_att_one():
    provision.validate_args(_args(max_att=1))


@pytest.mark.parametrize("iters", [0, 0x100000000])
def test_validate_args_rejects_kdf_iter_out_of_range(iters):
    with pytest.raises(provision.ProvisionError):
        provision.validate_args(_args(kdf_iter=iters))


# ----------------------------------------------------------------------------------------------
# generate_nvs_bin -- guardcfg size guards fire before the generator is ever invoked
# ----------------------------------------------------------------------------------------------

def _stub_gen_dir(tmp_path):
    d = tmp_path / "gendir"
    d.mkdir()
    # Discovery only checks the file exists; the size guards below reject before it is run.
    (d / "nvs_partition_gen.py").write_text("# stub -- never invoked on the rejection paths\n")
    return str(d)


def test_generate_nvs_bin_rejects_below_floor(tmp_path):
    csv = tmp_path / "in.csv"
    csv.write_text("key,type,encoding,value\n")
    with pytest.raises(provision.ProvisionError):
        provision.generate_nvs_bin(
            str(csv), str(tmp_path / "out.bin"), 0x2000, nvs_gen_dir=_stub_gen_dir(tmp_path)
        )


def test_generate_nvs_bin_rejects_non_4k(tmp_path):
    csv = tmp_path / "in.csv"
    csv.write_text("key,type,encoding,value\n")
    with pytest.raises(provision.ProvisionError):
        provision.generate_nvs_bin(
            str(csv), str(tmp_path / "out.bin"), 0x3001, nvs_gen_dir=_stub_gen_dir(tmp_path)
        )


# ----------------------------------------------------------------------------------------------
# build_manifest_files -- exactly one otadata seed (no collision), guardcfg always present
# ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("variant,partcsv", [
    ("fork", "suicide_4MB.csv"),
    ("guardian", "suicide_guardian_16MB.csv"),
])
def test_build_manifest_exactly_one_otadata_seed(tmp_path, variant, partcsv):
    parts = provision.parse_partitions_csv(os.path.join(PARTS_DIR, partcsv))
    guardcfg = provision.require_partition(parts, provision.GUARDCFG_PART)
    otadata = provision.require_partition(parts, provision.OTADATA_PART)
    args = argparse.Namespace(chip="esp32", variant=variant, build_dir=None, out=str(tmp_path))

    files, _warnings = provision.build_manifest_files(args, parts, guardcfg, otadata)

    on_otadata = [f["file"] for f in files if f["offset"] == otadata["offset"]]
    assert len(on_otadata) == 1
    names = [f["file"] for f in files]
    if variant == "guardian":
        assert on_otadata[0] == "otadata_blank.bin"
        # guardian seeds BOTH the factory Guardian and the unmodified Marauder in ota_0.
        assert "guardian.bin" in names and "marauder.bin" in names
    else:
        assert on_otadata[0] == "boot_app0.bin"
        assert "app.bin" in names

    gc = [f for f in files if f["file"] == "guardcfg.bin"]
    assert len(gc) == 1 and gc[0]["offset"] == guardcfg["offset"]


# ----------------------------------------------------------------------------------------------
# build_nvs_rows -- canonical sgate schema (namespace row first, exact keys/encodings)
# ----------------------------------------------------------------------------------------------

def test_build_nvs_rows_schema():
    salt = b"\x11" * provision.SALT_LEN
    pwhash = b"\x22" * provision.KDF_DKLEN
    rows = provision.build_nvs_rows(_args(), salt, pwhash)
    assert rows[0] == (provision.NVS_NAMESPACE, "namespace", "", "")
    keys = [r[0] for r in rows]
    for required in ("cfg_ver", "salt", "pwhash", "kdf_iter", "kdf_dklen", "armed", "max_att"):
        assert required in keys
    salt_row = next(r for r in rows if r[0] == "salt")
    assert salt_row[2] == "hex2bin" and salt_row[3] == salt.hex()
