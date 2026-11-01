"""Verify retained original producer and official SDK generation outputs after reactor verify."""
import hashlib
import json
from pathlib import Path
import stat
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'domain-core-security-center-web'
SDK = ROOT / 'domain-core-security-center-sdk'


def read(path, limit=8 * 1024 * 1024):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit or getattr(metadata, 'st_flags', 0) & 0x40000000:
        raise ValueError('Missing or unsupported generation output')
    return path.read_bytes()


def passed_tests(module, names):
    cases = {}
    for report in sorted((module / 'target/surefire-reports').glob('TEST-*.xml')):
        document = ET.fromstring(read(report))
        for case in document.iter('testcase'):
            name = case.get('name')
            if name not in names:
                continue
            if name in cases or any(case.find(tag) is not None for tag in ('failure', 'error', 'skipped')):
                raise ValueError('Required producer or SDK test did not uniquely pass')
            cases[name] = True
    if set(cases) != names:
        raise ValueError('Required producer or SDK tests were not executed')
    return sorted(cases)


def verify(root=ROOT):
    web = root / WEB.name
    sdk = root / SDK.name
    summary = json.loads(read(root / '.qualification/source-summary.json'))
    if summary.get('maven_exit') != 0:
        raise ValueError('Reactor verification did not succeed')
    required = {
        web: {'generatedReceiverContractDeclaresBearerAuthAndExcludesUnavailableCredentialOperations',
              'originalProducerPreservesAllVisibleBearerRequirementsAndStableConsumerOperations'},
        sdk: {'generatorInputMatchesTheOriginalProducerBearerOperations',
              'generatedAuthenticationIsOwnedByEachCallerClient',
              'twoOverlappingStaffCallsUseTheirOwnGeneratedBearerAuthentication',
              'generatedAccessDecisionDecodesBothAllowedAndDeniedBodies'},
    }
    observed = []
    for module, names in required.items():
        observed.extend(passed_tests(module, names))
    producer = web / 'target/receiver-openapi.json'
    selected = sdk / 'src/main/resources/openapi.yml'
    generated = sdk / 'target/generated-sources/src/gen/java/main/io/fireflysoftware/security/center/sdk'
    outputs = [producer, selected, generated / 'api/IdentityControllerApi.java',
               generated / 'invoker/ApiClient.java', generated / 'invoker/auth/HttpBearerAuth.java',
               generated / 'api/AccessControllerApi.java', generated / 'model/Subject.java', generated / 'model/AccessDecision.java']
    data = json.loads(read(producer))
    scheme = data['components']['securitySchemes']['bearerAuth']
    if scheme.get('type') != 'http' or scheme.get('scheme') != 'bearer':
        raise ValueError('Original producer lacks the required bearer scheme')
    identity = data['paths']['/api/v1/identity/subjects']['post']
    if identity.get('operationId') != 'resolveSubject' or identity.get('security') != [{'bearerAuth': []}]:
        raise ValueError('Original producer operation contract is incompatible')
    api = read(outputs[2]).decode('utf-8')
    if 'resolveSubject' not in api or '"bearerAuth"' not in api:
        raise ValueError('Official generated operation lacks bearer authentication')
    jar = sdk / 'target/domain-core-security-center-sdk-26.10.6.jar'
    read(jar, 32 * 1024 * 1024)
    with zipfile.ZipFile(jar) as archive:
        for name in ['api/IdentityControllerApi.class', 'api/AccessControllerApi.class', 'model/Subject.class',
                     'model/AccessDecision.class', 'invoker/ApiClient.class', 'invoker/auth/HttpBearerAuth.class']:
            archive.getinfo('io/fireflysoftware/security/center/sdk/' + name)
    outputs.append(jar)
    result = {
        'scope': 'Original producer and generated candidate SDK only; not published adoption or receiver acceptance',
        'requiredTestsPassed': observed,
        'producerAuthRequired': True,
        'generatedCallerIsolationTestPassed': True,
        'generatedDTOBodiesDecoded': True,
        'publishedSDKAdoption': False,
        'providerOrDelegationAccepted': False,
        'outputs': {str(path.relative_to(root)): hashlib.sha256(read(path, 32 * 1024 * 1024)).hexdigest()
                    for path in outputs},
    }
    (root / '.qualification/receiver-sdk-summary.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
