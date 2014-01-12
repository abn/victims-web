#!/usr/bin/env bash

python -c \
    "from flask.ext.script import Manager; \
    from victims_web.application import app; \
    Manager(app).run()" \
    shell
