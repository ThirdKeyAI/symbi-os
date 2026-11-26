"""Runtime checks select only the already signed iniparser from the build lock."""
import copy
import unittest

from image.portal.runtime_inputs import select_runtime_package


class PortalRuntimeSelection(unittest.TestCase):
    def fixture(self):
        row={'filename':'iniparser-4.2.6-5.fc45.x86_64.rpm','nevra':'iniparser-4.2.6-5.fc45.x86_64',
             'bytes':26470,'sha256':'a'*64,'key_fingerprint':'B'*40,'signature_verified':True,
             'license':'MIT','vendor':'Fedora Project'}
        return {'packages':[row,dict(row,filename='iniparser-devel-4.2.6-5.fc45.x86_64.rpm',nevra='iniparser-devel-4.2.6-5.fc45.x86_64')],
                'key':{'fingerprint':'B'*40}}

    def test_selects_exact_runtime_not_headers_or_other_build_packages(self):
        lock=self.fixture()
        self.assertEqual(select_runtime_package(lock),lock['packages'][0])

    def test_missing_ambiguous_unsigned_or_changed_identity_is_refused(self):
        for case in ('missing','duplicate','key','signature','filename','hash','oversize','architecture'):
            with self.subTest(case=case):
                lock=self.fixture();row=lock['packages'][0]
                if case=='missing':lock['packages'].pop(0)
                elif case=='duplicate':lock['packages'].append(copy.deepcopy(row))
                elif case=='key':row['key_fingerprint']='C'*40
                elif case=='signature':row['signature_verified']=False
                elif case=='filename':row['filename']='../'+row['filename']
                elif case=='hash':row['sha256']='bad'
                elif case=='oversize':row['bytes']=1024**2+1
                else:row['nevra']=row['nevra'].replace('x86_64','aarch64')
                with self.assertRaises(ValueError):select_runtime_package(lock)


if __name__=='__main__':unittest.main()
