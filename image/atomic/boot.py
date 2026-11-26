"""Boot one private qcow2 overlay of the installed Atomic disk without networking."""
import json
import os
from pathlib import Path
import subprocess
import time

from contract import firmware_arguments, sha256, unique_json, validate_report


def main():
    if os.geteuid()!=10001 or not Path('/run/.containerenv').exists():
        raise SystemExit('Use the unprivileged disposable hosted QEMU container')
    group=Path('/sys/fs/cgroup')/Path(Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]).relative_to('/')
    limits={name:(group/name).read_text().strip() for name in ('memory.max','memory.swap.max','cpu.max','pids.max')}
    process={k:v.strip() for k,v in (line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)}
    if (limits!={'memory.max':'3221225472','memory.swap.max':'0','cpu.max':'200000 100000','pids.max':'64'}
            or process['CapEff']!='0000000000000000' or process['NoNewPrivs']!='1'
            or not os.statvfs('/').f_flag & os.ST_RDONLY
            or not os.statvfs('/inputs/atomic.raw').f_flag & os.ST_RDONLY
            or sorted(p.name for p in Path('/sys/class/net').iterdir())!=['lo']):
        raise ValueError('QEMU container isolation changed')
    inputs=Path('/inputs');output=Path('/output')
    expected=unique_json((inputs/'expected.json').read_bytes())
    record={'schema':1,'passed':False,'guest_booted':False,'os_qualified':False,'release_qualified':False,
            'limits':limits,'probe_sha256':sha256(inputs/'guest.py'),
            'expected_sha256':sha256(inputs/'expected.json'),'unit_sha256':sha256(inputs/'o.service'),
            'status_unit_sha256':sha256(inputs/'s.service'),
            'nonce':expected['nonce'],'scope':'Offline Atomic development image installation and boot only'}
    child=None
    try:
        record['qemu_version']=subprocess.check_output(['/usr/bin/qemu-system-x86_64','--version'],text=True,timeout=15)
        record['tools']={name:sha256(Path('/usr/bin')/name) for name in ('qemu-system-x86_64','qemu-img')}
        with (output/'prepare.log').open('x') as log:
            subprocess.run(['/usr/bin/qemu-img','create','-f','qcow2','-F','raw','-b',
                            '/inputs/atomic.raw','/output/guest.qcow2'],stdout=log,stderr=subprocess.STDOUT,
                           check=True,timeout=30)
        command=['/usr/bin/qemu-system-x86_64','-machine','q35,dump-guest-core=off',
                 '-accel','tcg,thread=single','-cpu','max','-m','1536M','-smp','1',
                 '-nodefaults','-no-user-config','-no-reboot','-net','none',
                 '-smbios','type=1,manufacturer=Symbi-Test,product=Symbi-Hosted-Atomic-Probe',
                 '-drive','file=/output/guest.qcow2,format=qcow2,if=virtio',
                 '-device','virtio-rng-pci','-device','virtio-serial-pci',
                 '-chardev','file,id=report,path=/output/report.json',
                 '-device','virtserialport,chardev=report,name=org.symbi.atomic',
                 '-serial','file:/output/serial.log','-monitor','none','-display','none']+firmware_arguments(inputs)
        record['command']=command
        (output/'result.json').write_text(json.dumps(record,indent=2)+'\n')
        start=time.monotonic()
        with (output/'qemu.log').open('x') as log:
            child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                                   env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/output'})
            while child.poll() is None:
                for name,maximum in [('serial.log',2*1024**2),('qemu.log',1024**2),('report.json',128*1024)]:
                    path=output/name
                    if path.exists() and path.stat().st_size>maximum:
                        raise ValueError('Guest output exceeded its bound: '+name)
                if time.monotonic()-start>=900: raise TimeoutError('Atomic guest did not report and power off in 15 minutes')
                time.sleep(0.5)
        record['exit_code']=child.returncode;record['elapsed_seconds']=time.monotonic()-start
        if child.returncode!=0: raise RuntimeError('QEMU failed; inspect original logs')
        path=output/'report.json'
        if not path.is_file() or path.is_symlink() or not 0<path.stat().st_size<=128*1024:
            raise ValueError('Missing bounded guest observation')
        report=unique_json(path.read_bytes())
        validate_report(report,expected,expected['nonce'],record['probe_sha256'],record['expected_sha256'])
        record['boot_id']=report['boot_id'];record['passed']=True;record['guest_booted']=True
    except Exception as error:
        record['failure']=type(error).__name__+': '+str(error)
        raise
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired: child.kill();child.wait(timeout=10)
            record['passed']=False
        record['cgroup_final']={n:(group/n).read_text().strip() for n in (*limits,'memory.peak','memory.events','cpu.stat')}
        events=dict(line.split() for line in record['cgroup_final']['memory.events'].splitlines())
        if any(events.get(n)!='0' for n in ('oom','oom_kill','oom_group_kill')): record['passed']=False
        (output/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    if not record['passed']: raise RuntimeError('Atomic boot resource controls failed')


if __name__=='__main__': main()
