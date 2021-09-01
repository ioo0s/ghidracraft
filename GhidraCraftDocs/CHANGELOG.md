# Change Log of Ghidracraft

## Dev Version (Not Released Yet)

This is the changelog that is still not released. When released, this will have their own release name.

- A new dark-theme is introduced and set as default theme. Currently, this might introduce some color
problems. But we will gradually fix those.
- Some of the colors are now possible to be customized in Color.properties (see [Color Configuration](https://starcrossportal.github.io/ghidracraft-book/ghidracraft_changes/color_configuration.html))
- New feature: pcode patch. see [pcode patch doc](https://starcrossportal.github.io/ghidracraft-book/ghidracraft_changes/pcode_patch.html)
- Add IDA style (well, partially) variable default naming to the decompiler. (see [shorter name](https://starcrossportal.github.io/ghidracraft-book/ghidracraft_changes/shorter_names.html))
- Minor UI improvements (see [dark theme](https://starcrossportal.github.io/ghidracraft-book/ghidracraft_changes/dark_theme.html))
    - modernize the button style, windows 98 style shadow is finally gone
    - flatten some of the elements to look modern. Still, get away from windows 98 styling.
- Minor improvements to the decompiler
    - a new rewrite rule rewrites `CONCAT` to shift, cast and then add operations (flattened)
    - supports float displaying in decompiler panel
- Bug fixes (incomplete list)
    - disallow rename to constant value in decompiler panel