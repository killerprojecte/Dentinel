from __future__ import annotations

import hashlib
import json
import mmap
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dentinel.common import sha256, write_json
from dentinel.license_state import FEATURES, LIMITS, MARKER, locate, matching, plan
from dentinel.oci import BINARY_PATH, START_PATH, Image, unpack_layout, verify_publish
from dentinel.patcher import EnterpriseStatePatcher, apply_patch, verify_candidate
from dentinel.sea import read_source
from dentinel import pipeline
from patch_fixtures import license_source, sea_elf
from test_oci import make_image, entry


class EnterpriseStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.write_bytes(sea_elf())
        self.output = self.root / "patched"

    def tearDown(self):
        self.temp.cleanup()

    def apply(self):
        return EnterpriseStatePatcher().apply(self.source, self.output, sha256(self.source))

    def test_sea_reader_preserves_assets_and_exec_argv(self):
        for flags in (1, 9, 25):
            with self.subTest(flags=flags):
                sea = read_source(sea_elf(flags=flags))
                self.assertEqual(sea.flags, flags)
                self.assertEqual(sea.code, license_source())
                self.assertEqual(sea.code_path, ".bundle/start.js")

    def test_only_exact_loader_range_changes(self):
        original = self.source.read_bytes()
        recipe = plan(self.source)
        result = self.apply()
        changed = self.output.read_bytes()
        size, start = len(recipe.original), recipe.offset
        self.assertEqual(len(changed), len(original))
        self.assertEqual(changed[:start], original[:start])
        self.assertEqual(changed[start + size:], original[start + size:])
        self.assertIn(MARKER, changed[start:start + size])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertTrue(result.functional_patch_applied)
        self.assertEqual(result.details["match_count"], 1)
        self.assertEqual(read_source(changed).source_size, recipe.sea.source_size)
        self.assertEqual(verify_candidate(self.source, self.output, "enterprise-state")["output_sha256"], result.output_sha256)

    def test_update_offset_and_obfuscated_names_are_relocated(self):
        for cls, instance, state in (("OtherLic", "otherInstance", "otherStatus"), ("$L$", "$instance", "$status")):
            with self.subTest(cls=cls):
                self.source.write_bytes(sea_elf(b"/*new-build-prefix*/\n" + license_source(class_name=cls, instance=instance, status=state), note_offset=4096))
                recipe = plan(self.source)
                self.assertEqual((recipe.class_name, recipe.instance_name, recipe.status_name), (cls, instance, state))
                result = self.apply()
                self.assertEqual(result.details["local_state"]["plan"], "enterprise")
                self.output.unlink()

    def test_duplicate_and_missing_features_fail_without_output(self):
        sources = (
            license_source() + license_source(class_name="Other", instance="other", status="otherStatus"),
            license_source().replace(b"get features()", b"get removedFeatures()"),
            license_source().replace(b"async load(e)", b"async load(e, options)"),
            license_source(filler=0),
        )
        for code in sources:
            with self.subTest(code_size=len(code)):
                self.source.write_bytes(sea_elf(code))
                with self.assertRaises(ValueError):
                    self.apply()
                self.assertFalse(self.output.exists())

    def test_unknown_feature_limit_and_computed_access_fail(self):
        for access in (
            b"lic.features?.newCapability", b"lic.limits?.tokens", b"lic.data?.license.limits.tokens",
            b"lic.features?.[key]", b"lic.limits[key]", b'lic.data?.license.features["newCapability"]',
            b"lic.data?.license?.limits?.[key]", b"lic?.features?.newCapability", b"lic?.limits?.tokens",
            b"lic?.data?.license?.features?.newCapability", b"lic?.features?.[key]",
            b'lic.data["license"].features.rbac', b'lic.data?.license["features"].rbac',
            b"lic . data ?. license . features [key]",
        ):
            with self.subTest(access=access):
                self.source.write_bytes(sea_elf(license_source() + b";var bad=" + access + b";"))
                with self.assertRaises(ValueError):
                    self.apply()
                self.assertFalse(self.output.exists())

    def test_loader_parameter_shadowing_fails_without_output(self):
        for name in (b"unlicensed", b"Object", b"clearTimeout"):
            with self.subTest(name=name):
                code = license_source().replace(b"async load(e)", b"async load(" + name + b")")
                code = code.replace(b"this.hello(e)", b"this.hello(" + name + b")")
                self.source.write_bytes(sea_elf(code))
                with self.assertRaisesRegex(ValueError, "shadows"):
                    self.apply()
                self.assertFalse(self.output.exists())

    def test_control_condition_regex_does_not_truncate_loader(self):
        code = license_source().replace(b"return this.data\n}", b"if(e)/}/.test(e);return this.data\n}")
        self.source.write_bytes(sea_elf(code))
        recipe = plan(self.source)
        self.assertIn(b"if(e)/}/.test(e);return this.data", recipe.original)
        self.assertEqual(recipe.class_end, code.index(b";\nvar lic=new Lic;"))
        self.apply()
        self.assertNotIn(b"if(e)/}/.test(e);return this.data", read_source(self.output.read_bytes()).code)

    def test_control_regex_and_division_delimiters(self):
        for code in (
            b"{if(e)/}/.test(e);}", b"{if((e))/}/.test(e);}",
            b"{while(e)/}/.test(e);}", b"{for(;e;)/}/.test(e);}",
            b"{if(e){}else /}/.test(e);}", b"{let n=Math.floor(123)/100;}",
            b"{thing.if(e)/2;}",
        ):
            with self.subTest(code=code):
                self.assertEqual(matching(code, 0), len(code))
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            matching(b"{if(e){} /}/.test(e);}", 0)

    def test_bad_elf_note_and_snapshot_fail_closed(self):
        samples = [b"not-elf", sea_elf(duplicate_note=True), sea_elf(flags=3), sea_elf(flags=5), sea_elf(flags=0x29)]
        truncated = sea_elf()[:-100]
        samples.append(truncated)
        invalid_arch = bytearray(sea_elf())
        struct.pack_into("<H", invalid_arch, 18, 183)
        samples.append(bytes(invalid_arch))
        for raw in samples:
            with self.subTest(length=len(raw)):
                self.source.write_bytes(raw)
                with self.assertRaises(ValueError):
                    self.apply()
                self.assertFalse(self.output.exists())

    def test_repatch_wrong_preimage_and_extra_change_are_rejected(self):
        before = sha256(self.source)
        self.apply()
        with self.assertRaisesRegex(ValueError, "already"):
            EnterpriseStatePatcher().apply(self.output, self.root / "again", sha256(self.output))
        self.assertFalse((self.root / "again").exists())
        with self.assertRaisesRegex(ValueError, "hash"):
            EnterpriseStatePatcher().apply(self.source, self.root / "wrong", "0" * 64)
        data = bytearray(self.output.read_bytes())
        data[-1] ^= 1
        self.output.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "source-derived"):
            verify_candidate(self.source, self.output, "enterprise-state")
        self.assertEqual(sha256(self.source), before)

    def test_patch_report_is_honest_and_separate(self):
        report = self.root / "patch-report.json"
        result = apply_patch(self.source, self.output, sha256(self.source), report, "enterprise-state")
        saved = json.loads(report.read_bytes())
        self.assertEqual(saved["mode"], "enterprise-state")
        self.assertFalse(saved["details"]["local_state"]["vendor_signed"])
        self.assertTrue(saved["details"]["vendor_crypto_unchanged"])
        self.assertEqual(saved["output_sha256"], result.output_sha256)
        with self.assertRaises(ValueError):
            apply_patch(self.source, self.root / "new", sha256(self.source), self.root / "new", "enterprise-state")
        self.assertFalse((self.root / "new").exists())

    def test_malformed_js_delimiters_fail(self):
        with self.assertRaises(ValueError):
            matching(b"{unterminated(`template ${1}", 0)
        with self.assertRaises(ValueError):
            matching(b"{)]}", 0)
        code = b'{let x=/[{}]/;let y=`${{x:"}"}.x}`;}'
        self.assertEqual(matching(code, 0), len(code))

    def test_real_recipe_oci_round_trip_offline(self):
        work = self.root / "work"
        base = Image(make_image(work / "upstream", [[entry(BINARY_PATH, self.source.read_bytes()), entry(START_PATH, b"#!/bin/sh\n")]]))
        lock = {"source": "fixture", "digest": base.digest, "pinned": "example@" + base.digest, "platform": "linux/amd64"}
        write_json(work / "source-lock.json", lock)
        pipeline.extract(base.root, work / "original", lock)
        with patch("socket.socket.connect", side_effect=AssertionError("Network prohibited")), patch("subprocess.run", side_effect=AssertionError("No external process")):
            pipeline.patch(work / "original", work / "patched-enterprise", "enterprise-state")
            report = pipeline.rebuild(work, patched=work / "patched-enterprise", output=work / "enterprise")
            self.assertTrue(report["functional_patch_applied"])
            self.assertEqual(report["mode"], "enterprise-state")
            restored = unpack_layout(work / "enterprise/dentinel.oci.tar", work / "restored")
            verify_publish(restored)
        self.assertEqual((work / "original/altcha-sentinel").read_bytes(), self.source.read_bytes())
        # A forged report or extra changed byte cannot weaken verification.
        candidate = work / "patched-enterprise/altcha-sentinel"
        data = bytearray(candidate.read_bytes())
        data[-1] ^= 1
        candidate.write_bytes(data)
        saved = json.loads((work / "patched-enterprise/patch-report.json").read_bytes())
        saved["output_sha256"] = sha256(candidate)
        write_json(work / "patched-enterprise/patch-report.json", saved, replace=True)
        with self.assertRaises(ValueError):
            pipeline.rebuild(work, patched=work / "patched-enterprise", output=work / "forged")
        self.assertFalse((work / "forged/result").exists())

    @unittest.skipUnless(shutil.which("node"), "Node is required only for the isolated JS behavioral test")
    def test_isolated_state_resists_refresh_overwrites_without_network(self):
        self.apply()
        code = read_source(self.output.read_bytes()).code.decode()
        script = r'''
const vm=require("node:vm");let network=0,timers=0,clears=[],writes=0;
const context={fetch:()=>{network++;throw Error("network prohibited")},setTimeout:()=>{timers++;throw Error("timers prohibited")},clearTimeout:id=>clears.push(id),persist:()=>writes++};
vm.createContext(context);new vm.Script(SOURCE).runInContext(context);
(async()=>{const result=await vm.runInContext(`(async()=>{unlicensed=2;lic.loadTimeout=17;await lic.load();let d=lic.data;lic.data={license:{plan:"starter"}};lic.licenseId="other";lic.loadIntervalSec=123;try{d.license.features.rbac=false}catch{}try{d.license.limits.instances=1}catch{}await lic.load("reload");await lic.writeLicense({license:{id:"bad"}});const hello=await lic.hello(),check=await lic.check("ignored"),verified=await lic.verifySignature(d);return {plan:lic.plan,features:lic.features,limits:lic.limits,status:getStatus(),licenseId:lic.licenseId,loadIntervalSec:lic.loadIntervalSec,loadTimeout:lic.loadTimeout,sameObject:lic.data===d,helloSame:hello===d,check,originalVerifier:verified.verified,vendorSigned:!!d.signature}})()`,context);console.log(JSON.stringify({...result,network,timers,clears,writes}))})().catch(e=>{console.error(e);process.exitCode=1});
'''.replace("SOURCE", json.dumps(code))
        result = subprocess.run(["node", "-"], input=script, text=True, encoding="utf-8", capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(result.stdout)
        self.assertEqual(state["plan"], "enterprise")
        self.assertEqual(state["features"], FEATURES)
        self.assertEqual(state["limits"], LIMITS)
        self.assertEqual(state["status"], 0)
        self.assertEqual(state["licenseId"], "dentinel-local")
        self.assertEqual(state["loadIntervalSec"], 0)
        self.assertIsNone(state["loadTimeout"])
        self.assertTrue(state["sameObject"])
        self.assertTrue(state["helloSame"])
        self.assertFalse(state["originalVerifier"])
        self.assertFalse(state["vendorSigned"])
        self.assertEqual((state["network"], state["timers"], state["writes"]), (0, 0, 0))
        self.assertEqual(state["clears"], [17])


if __name__ == "__main__":
    unittest.main()
