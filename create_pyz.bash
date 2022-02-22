#!/bin/bash

tmpdir=$(mktemp -d) || exit 1

# check if python supports zipapp compression
zipapp="python3 -m zipapp"
if python3 -m zipapp --help | grep -q -- --compress; then
    zipapp="$zipapp --compress"
fi

# define script name
project_script=$(basename $(pwd))
if [ -f ${project_script}.py ]; then
    script=${project_script}
else
    script=${script:-$(ls -1 *.py | sed -n '1s/\.py//p')}
fi

cp $script.py $tmpdir/__main__.py
for f in *.py; do
    if [ "$f" != "$script.py" ]; then
        cp $f $tmpdir/
    fi
done

requirements=$(cat requirements.txt)
if python3 -c 'import requests' 2>/dev/null; then
    requirements=$(grep -iv requests requirements.txt)
fi
python3 -m pip install $requirements --target $tmpdir
$zipapp --python "/usr/bin/env python3" --output $script.pyz $tmpdir
rm -r $tmpdir
