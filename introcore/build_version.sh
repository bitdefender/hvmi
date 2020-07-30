#!/bin/bash
##
## Copyright (c) 2020 Bitdefender
## SPDX-License-Identifier: Apache-2.0
##

# Exit on any error
set -euo pipefail
IFS=$'\n\t'

branch=$(git rev-parse --abbrev-ref HEAD)
buildmachine=$(hostname)
buildnumber=$(git rev-list --count HEAD)
changeset=$(git rev-parse --short HEAD)

major=$(grep -o -P "Major\s+=\s+\K[0-9].*" ../../config/hvmi.cfg)
minor=$(grep -o -P "Minor\s+=\s+\K[0-9].*" ../../config/hvmi.cfg)
revision=$(grep -o -P "Revision\s+=\s+\K[0-9].*" ../../config/hvmi.cfg)

if [ ! -d ../../autogen ]; then
    mkdir ../../autogen
fi

echo -ne "#ifndef __VER_H__\n#define __VER_H__\n\n#define INTRO_VERSION_BRANCH            \"$branch\"\n#define INTRO_VERSION_BUILDMACHINE      \"$buildmachine\"\n#define INTRO_VERSION_BUILDNUMBER       $buildnumber\n#define INTRO_VERSION_CHANGESET         \"$changeset\"\n#define INTRO_VERSION_GITBRANCH         \"$branch\"\n#define INTRO_VERSION_GITLOCALREVISION  $buildnumber\n#define INTRO_VERSION_LOCALREVISION     $buildnumber\n#define INTRO_VERSION_MAJOR             $major\n#define INTRO_VERSION_MINOR             $minor\n#define INTRO_VERSION_REVISION          $revision\n\n#endif" > ../../autogen/ver.h

sed -i "s/project_version.*/project_version $major.$minor.$revision)/" project-meta-info.in
