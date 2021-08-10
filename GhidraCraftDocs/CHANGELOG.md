# Change Log of Ghidracraft

## Dev Version (Not Released Yet)

This is the changelog that is still not released. When released, this will have their own release name.

- A new dark-theme is introduced and set as default theme. Currently, this might introduce some color
problems. But we will gradually fix those.
- Some of the colors are now possible to be customized in Color.properties (see [color customization doc](./ghidracraft/color_customize.md))
- New feature: pcode patch. see [pcode patch doc](./ghidracraft/pcode_patch.md)
- Add IDA style (well, partially) variable default naming to the decompiler. (can be enabled by Edit -> Tool Options -> Decompiler -> Analysis -> Short variable names)
- Minor UI improvements
    - modernize the button style, windows 98 style shadow is finally gone
    ![button shadow](./imgs/changelog/dev/button_shadow.png)
    - flatten some of the elements to look modern. Still, get away from windows 98 styling.
    ![flattened elements](./imgs/changelog/dev/flatten.png)
- Minor improvements to the decompiler
    - `CONCAT` is now decompiled to shift, cast and then add operations (flattened)
    - supports float displaying in decompiler panel
- Bug fixes (incomplete list)
    - disallow rename to constant value in decompiler panel