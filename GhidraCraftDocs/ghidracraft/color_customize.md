# Color Customization

## Why

Originally, Ghidra has hard-coded colors everywhere.
Although it supports customizable java swing color theme, many of the hard-coded colors are still
a problem.
This happens when we are trying to add the dark-theme as the default theme. Many of the colors are
hard to be seen under new added theme as they are hard coded.

## Solution

A new `Color.properties` file is added to the final output, path is
`GHIDRACRAFT_INSTALLATION/support/Color.properties`.

Some of the colors are defined there, and ghidracraft may look at that file to determine the actual
color instead of hard-coding them.

Note that this is a gradual procedure, meaning that this is still not complete. Colors will be added
gradually since Ghidra has way TOO MANY hard-coded colors. And it's time-consuming to modify those
at once.

[[TODO: introduce each color name of what they are referring to]]