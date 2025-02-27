import pytest

from detect_secrets.plugins.npm import NpmDetector


class TestNpmDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('//registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', True),
            ('//registry.npmjs.org/:_authToken=346a14f2-a672-4668-a892-956a462ab56e', True),
            ('//registry.npmjs.org/:_authToken= 743b294a-cd03-11ec-9d64-0242ac120002', True),
            ('//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxx', True),
            ('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', True),
            ('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', True),
            ('npm_Mm9aV8acPGWEfdtooshortTOOSHO000OORT', False),
            ('//registry.npmjs.org:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('///:_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('_authToken=743b294a-cd03-11ec-9d64-0242ac120002', False),
            ('foo', False),
            ('//registry.npmjs.org/:_authToken=${NPM_TOKEN}', False),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = NpmDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
