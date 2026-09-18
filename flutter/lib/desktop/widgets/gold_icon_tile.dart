import 'package:flutter/material.dart';

/// Small rounded-square accent tile used across the Protork home screen:
/// a solid gold background with a dark icon centered inside. Used as the
/// leading accent for sidebar rows (see desktop_home_page.dart) and section
/// headers (see connection_page_title.dart) instead of the plain accent bar
/// / uncolored icon used previously.
class GoldIconTile extends StatelessWidget {
  final IconData icon;
  final double size;
  final double iconSize;
  final Color background;
  final Color iconColor;

  const GoldIconTile({
    Key? key,
    required this.icon,
    this.size = 30,
    this.iconSize = 16,
    this.background = const Color(0xFFFFD600),
    this.iconColor = const Color(0xFF111111),
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(size * 0.28),
      ),
      alignment: Alignment.center,
      child: Icon(icon, size: iconSize, color: iconColor),
    );
  }
}
