"""Small synthetic ELF/SEA samples; never embed the proprietary application."""

import struct


def license_source(*, class_name="Lic", instance="lic", status="unlicensed", filler=2400):
    text = r'''
var STATUS=0;
function setStatus(e){STATUS=e}
function resetStatus(){STATUS=0}
function getStatus(){return STATUS}
var middleware=()=>{if(STATUS===2)throw Error("x-unlicensed");return STATUS};
var CLASS=class{
LICENSE_SERVER="https://unused.invalid/license";
KNOWN_PUBLIC_KEYS=[];
licenseId="";data=null;loadTimeout=null;loadIntervalSec=3600;
get features(){return this.data?.license?.features||null}
get limits(){return this.data?.license?.limits||null}
get plan(){return this.data?.license?.plan||null}
async load(e){
let text="a } brace",pattern=/license\.(\w+)(\w{4})/g,template=`nested ${{a:"}"}.a} ${`more ${1+2}`}`;
if(this.loadTimeout)clearTimeout(this.loadTimeout);
this.data=await this.hello(e);
await this.verifySignature(this.data);
this.loadTimeout=setTimeout(()=>this.load(),this.loadIntervalSec*1000);
/*FILLER*/
return this.data
}
async hello(e){return fetch(this.LICENSE_SERVER)}
async check(e){return fetch(this.LICENSE_SERVER)}
async verifySignature(e){return {verified:false,license:e?.license}}
async validate(e){return (await this.verifySignature(e)).verified}
async writeLicense(e){return persist(e)}
};
var INSTANCE=new CLASS;
var observed=()=>[INSTANCE.features?.rbac,INSTANCE.features?.trial,INSTANCE.features?.clickhouse,INSTANCE.limits?.instances,INSTANCE.limits?.throttle,INSTANCE.limits?.users,INSTANCE.limits?.accounts,INSTANCE.data?.license.features.accessLogs];
'''
    return text.replace("FILLER", "x" * filler).replace("CLASS", class_name).replace("INSTANCE", instance).replace("STATUS", status).encode("ascii")


def sea_elf(code=None, *, note_offset=1024, flags=9, duplicate_note=False, assets=None):
    code = license_source() if code is None else code
    assets = {b"sample": b"leave-this-asset-unchanged\x00\xff"} if assets is None else assets
    string = lambda data: struct.pack("<Q", len(data)) + data
    blob = struct.pack("<IIB", 0x143DA20, flags, 1)
    blob += string(b".bundle/start.js") + string(code)
    if flags & 8:
        blob += struct.pack("<Q", len(assets))
        for name, content in assets.items():
            blob += string(name) + string(content)
    if flags & 16:
        blob += struct.pack("<Q", 1) + string(b"--no-warnings")
    note_name = b"NODE_SEA_BLOB\0"
    note = struct.pack("<III", len(note_name), len(blob), 0) + note_name
    note += b"\0" * (-len(note) % 4) + blob
    note += b"\0" * (-len(note) % 4)
    notes = note * (2 if duplicate_note else 1)
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 4, 4, note_offset, note_offset, note_offset, len(notes), len(notes), 4)
    return (header + ph).ljust(note_offset, b"\0") + notes + b"UNRELATED_ELF_TRAILER"
