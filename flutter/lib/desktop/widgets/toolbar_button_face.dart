import 'package:flutter/material.dart';

/// A menu's label receives loose constraints. Keep its artwork finite even
/// inside a scrolling toolbar, and never paint an oversized SVG over a session.
class ToolbarButtonFace extends StatelessWidget {
  final double width;
  final double height;
  final BoxDecoration decoration;
  final Widget icon;

  const ToolbarButtonFace({
    super.key,
    required this.width,
    required this.height,
    required this.decoration,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) => SizedBox(
        width: width,
        height: height,
        child: DecoratedBox(
          decoration: decoration,
          child: ClipRect(
            child: Padding(
              padding: const EdgeInsets.all(7),
              child: Center(
                child: FittedBox(fit: BoxFit.scaleDown, child: icon),
              ),
            ),
          ),
        ),
      );
}
