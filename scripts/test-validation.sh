#!/bin/bash
# Simple test of the security validation logic

echo "Testing commit 241aa3ba (known false positive):"
echo "Message claims security fix:"
git log --format=%B -n 1 241aa3ba | head -1

echo "Files actually changed:"
git show --name-only --format= 241aa3ba

echo ""
echo "Testing commit 7612f421 (my legitimate security fix):"
echo "Message claims security fix:"
git log --format=%B -n 1 7612f421 | head -1

echo "Files actually changed:"
git show --name-only --format= 7612f421

echo ""
echo "Expected: 241aa3ba should be flagged invalid, 7612f421 should be valid"