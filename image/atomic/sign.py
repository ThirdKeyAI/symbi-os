"""Ephemeral offline CI signing and real image-policy negative controls."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tarfile

from bounded_process import run_bounded
from contract import digest_value, installer_policy, require_verifier_identity, sha256, unique_json


def main():
    if (os.geteuid()!=10001 or not Path('/run/.containerenv').exists()
            or sorted(path.name for path in Path('/sys/class/net').iterdir())!=['lo']):
        raise SystemExit('Use the offline unprivileged hosted signing container')
    group=Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
    limits={name:(group/name).read_text().strip() for name in ('memory.max','memory.swap.max','cpu.max','pids.max')}
    if limits!={'memory.max':'1073741824','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'64'}:
        raise ValueError('Unexpected ephemeral signing limits')
    output=Path('/output');private=output/'private';private.mkdir(mode=0o700)
    evidence=output/'evidence';evidence.mkdir(mode=0o700)
    manifest=Path('/inputs/manifest.json')
    expected=unique_json(Path('/inputs/sign.json').read_bytes())
    if sha256(manifest)!=digest_value(expected['manifest_digest']):
        raise ValueError('Verified development manifest changed')
    record={'passed':False,'release_qualified':False,'source_manifest_digest':expected['manifest_digest'],
            'scope':'Ephemeral local CI fixture key; never the ThirdKey release identity',
            'limits':limits,'commands':[],'negative_controls':{}}
    def run(name,command,timeout=60,check=True):
        result=run_bounded(command,evidence/(name+'-stdout.log'),evidence/(name+'-stderr.log'),timeout,65536)
        record['commands'].append({'name':name,'exit_code':result.returncode})
        if check: result.check_returncode()
        return result
    homes=[]
    try:
        version=run('skopeo-version',['/usr/bin/skopeo','--version']).stdout
        package=run('skopeo-package',['/usr/bin/rpm','-q','skopeo','--qf',
                                    '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n']).stdout
        require_verifier_identity(version,package)
        record['verifier']={'version':version.strip(),'rpm_identity':package.strip()}
        keys=[]
        for name in ('good','wrong'):
            home=private/name;home.mkdir(mode=0o700);homes.append(home)
            gpg=['/usr/bin/gpg','--no-options','--homedir',str(home),'--batch','--pinentry-mode','loopback','--passphrase','']
            run('generate-'+name,gpg+['--quick-generate-key','Symbi CI ephemeral '+name+' test key','ed25519','sign','0'],120)
            listed=run('fingerprint-'+name,gpg+['--with-colons','--list-keys'])
            fingerprints=[line.split(':')[9] for line in listed.stdout.splitlines() if line.startswith('fpr:')]
            if len(fingerprints)!=1 or len(fingerprints[0])!=40:
                raise ValueError('Unexpected ephemeral test key identities')
            public=output/(name+'-public.asc')
            run('export-public-'+name,gpg+['--armor','--output',str(public),'--export',fingerprints[0]])
            if not public.read_bytes().startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'):
                raise ValueError('Expected only an exported public key')
            keys.append((home,fingerprints[0],public))
        def sign(name,source,reference,key,destination):
            home,fingerprint,_=key
            run(name,['/usr/bin/env','GNUPGHOME='+str(home),'/usr/bin/skopeo','standalone-sign',
                      str(source),reference,fingerprint,'--output',str(destination)])

        # A tiny valid OCI image exercises the actual signature-policy engine.
        # The successful control precedes mutations of only signature/identity.
        fixture=output/'policy-source';fixture.mkdir(mode=0o700)
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w') as archive:
            data=b'bounded offline signature fixture\n';member=tarfile.TarInfo('fixture');member.size=len(data)
            archive.addfile(member,io.BytesIO(data))
        unpacked=raw.getvalue();layer=gzip.compress(unpacked,mtime=0)
        config=json.dumps({'architecture':'amd64','os':'linux','config':{},
                          'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(unpacked).hexdigest()]}}).encode()
        def blob(data,media):
            digest=hashlib.sha256(data).hexdigest();(fixture/digest).write_bytes(data)
            return {'mediaType':media,'digest':'sha256:'+digest,'size':len(data)}
        mini={'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json',
              'config':blob(config,'application/vnd.oci.image.config.v1+json'),
              'layers':[blob(layer,'application/vnd.oci.image.layer.v1.tar+gzip')]}
        mini_manifest=fixture/'manifest.json';mini_manifest.write_text(json.dumps(mini)+'\n')
        (fixture/'version').write_text('Directory Transport Version: 1.1\n')
        reference='localhost/symbi-ci/development@sha256:'+sha256(mini_manifest)
        public_key=keys[0][2].read_bytes()
        policy=installer_policy({'default':[{'type':'reject'}],'transports':{'docker':{}}},public_key,'sha256:'+sha256(mini_manifest))
        policy['transports']['dir'][str(fixture)]=policy['transports']['dir'].pop('/inputs/signed')
        policy_path=output/'fixture-policy.json';policy_path.write_text(json.dumps(policy)+'\n')
        signature=fixture/'signature-1'
        sign('sign-control',mini_manifest,reference,keys[0],signature)
        good_signature=signature.read_bytes()
        def copy_control(name,success):
            destination=output/('copy-'+name)
            result=run('policy-'+name,['/usr/bin/skopeo','--policy',str(policy_path),'copy','--preserve-digests',
                       'dir:'+str(fixture),'dir:'+str(destination)],check=False)
            if (result.returncode==0)!=success:
                raise ValueError('Unexpected actual image-policy result: '+name)
            if success and sha256(destination/'manifest.json')!=sha256(mini_manifest):
                raise ValueError('Policy control changed the manifest')
            if destination.exists(): shutil.rmtree(destination)
        copy_control('valid',True)
        for case in ('unsigned','wrong-key','wrong-reference','altered-signature'):
            signature.unlink(missing_ok=True)
            if case=='wrong-key': sign('sign-wrong-key',mini_manifest,reference,keys[1],signature)
            elif case=='wrong-reference': sign('sign-wrong-reference',mini_manifest,reference.replace('/development@','/unapproved@'),keys[0],signature)
            elif case=='altered-signature':
                changed=bytearray(good_signature);changed[len(changed)//2]^=1;signature.write_bytes(changed)
            copy_control(case,False);record['negative_controls'][case]=True
        shutil.rmtree(fixture)
        development_reference='localhost/symbi-ci/development@'+expected['manifest_digest']
        sign('sign-development',manifest,development_reference,keys[0],output/'signature-1')
        source_controls={'unsigned':None}
        negative=output/'negative-wrong-key-signature-1'
        sign('sign-development-wrong-key',manifest,development_reference,keys[1],negative)
        source_controls['wrong-key']=sha256(negative)
        negative=output/'negative-wrong-reference-signature-1'
        sign('sign-development-wrong-reference',manifest,
             development_reference.replace('/development@','/unapproved@'),keys[0],negative)
        source_controls['wrong-reference']=sha256(negative)
        negative=output/'negative-altered-signature-signature-1'
        changed=bytearray((output/'signature-1').read_bytes());changed[len(changed)//2]^=1
        negative.write_bytes(changed)
        source_controls['altered-signature']=sha256(negative)
        verified=run('verify-development',['/usr/bin/skopeo','standalone-verify','--public-key-file',str(keys[0][2]),
                     str(manifest),development_reference,keys[0][1],str(output/'signature-1')])
        if expected['manifest_digest'] not in verified.stdout:
            raise ValueError('Development signature verification did not identify the exact digest')
        record.update(passed=True,public_key_fingerprint=keys[0][1],public_key_sha256=sha256(keys[0][2]),
                      signature_sha256=sha256(output/'signature-1'),positive_policy_control=True,
                      negative_source_signatures=source_controls)
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
        raise
    finally:
        for index,home in enumerate(homes):
            stopped=run('stop-agent-'+str(index),['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'],check=False)
            if stopped.returncode!=0: record['passed']=False
        shutil.rmtree(private);record['private_keys_removed']=not private.exists()
        final={name:(group/name).read_text().strip() for name in (*limits,'memory.peak','memory.events','cpu.stat')}
        record['cgroup_final']=final
        events=dict(line.split() for line in final['memory.events'].splitlines())
        if any(final[name]!=value for name,value in limits.items()) or any(events.get(name)!='0' for name in ('oom','oom_kill','oom_group_kill')):
            record['passed']=False
        (evidence/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    if not record['passed']: raise RuntimeError('Ephemeral source authentication failed')


if __name__=='__main__': main()
