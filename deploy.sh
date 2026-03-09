#!/bin/bash

hexo clean
hexo g

git add .
git commit -m "update blog"
git push