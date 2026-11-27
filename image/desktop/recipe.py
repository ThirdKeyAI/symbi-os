"""Extend the pinned foundation recipe with the reviewed desktop payload."""
import re
import shlex

from image.recipe import render


def render_desktop(pins, variant, root, media_ready=False):
    recipe = render(pins, variant, root)
    foundation = recipe['modules'][0]['snippets']
    snippets = [
        'RUN --mount=type=bind,src=install-inputs,dst=/symbi-build-inputs,ro '
        'PYTHONDONTWRITEBYTECODE=1 python3 /symbi-build-inputs/install.py',
    ]
    if media_ready:
        snippets.append(
            'RUN --mount=type=bind,src=install-inputs,dst=/symbi-build-inputs,ro '
            'PYTHONDONTWRITEBYTECODE=1 python3 /symbi-build-inputs/media/media_install.py')
    snippets.append('COPY --chown=0:0 payload/ /')
    for instruction in foundation:
        snippets.append(instruction)
        if instruction == 'COPY image/overlay/ /':
            snippets.append('COPY image/desktop/session/ /')
    recipe['modules'][0]['snippets'] = snippets
    recipe['metadata']['description'] = 'Highly experimental Symbi OS desktop development image'
    return recipe


def review_containerfile(text, recipe, base):
    """Only the expected local stages, exact recipe and embedded scripts may run."""
    instructions = []
    pending = ''
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.endswith('\\'):
            pending += line[:-1].strip()+' '
        else:
            instructions.append(pending+line)
            pending = ''
    if pending or not instructions or instructions[0] != 'ARG BASE_IMAGE="'+base+'"':
        raise ValueError('Generated build does not begin with the authenticated base')
    name = recipe['metadata']['name']
    expected_from = ['FROM "${BASE_IMAGE}" AS '+name, 'FROM scratch AS stage-files',
                     'FROM scratch AS stage-keys', 'FROM '+name]
    if instructions[1:2] != expected_from[:1] or [s for s in instructions if s.startswith('FROM ')] != expected_from:
        raise ValueError('Generated build introduced another image or stage')
    script = 'RUN --mount=type=bind,src=.bluebuild-scripts_a654ee88,dst=/scripts/,ro /scripts/'
    expected_effects = [script+'pre_build.sh', *recipe['modules'][0]['snippets'], script+'post_build.sh']
    if [s for s in instructions if s.split()[0] in ('RUN', 'COPY', 'ADD')] != expected_effects:
        raise ValueError('Generated commands differ from the reviewed recipe')
    allowed_args = {'ARG TARGETARCH', 'ARG IMAGE_REGISTRY=ghcr.io/thirdkeyai', 'ARG BB_BUILD_FEATURES="bootc"',
                    'ARG CONFIG_DIRECTORY="/tmp/files"', 'ARG MODULE_DIRECTORY="/tmp/modules"',
                    'ARG IMAGE_NAME="'+name+'"', 'ARG BASE_IMAGE="'+base.split('@')[0]+'"'}
    for index, instruction in enumerate(instructions):
        verb = instruction.split()[0]
        if verb in ('FROM', 'RUN', 'COPY') or index == 0:
            continue
        if verb == 'WORKDIR' and instruction == 'WORKDIR /files':
            continue
        if instruction in allowed_args:
            continue
        if re.fullmatch(r'ARG RECIPE=/[A-Za-z0-9_./-]+\.json', instruction):
            continue
        if verb == 'LABEL':
            values = shlex.split(instruction)
            if len(values) == 2 and re.fullmatch(r'[a-zA-Z0-9_.-]+=.*', values[1]):
                continue
        raise ValueError('Unexpected generated instruction: '+instruction[:120])
