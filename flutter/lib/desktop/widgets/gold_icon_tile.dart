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
    this.background = const Color(0xFF37300A),
    this.iconColor = const Color(0xFFFFDE00),
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [background, const Color(0xFF090B06)],
        ),
        border: Border.all(color: const Color(0xFF756414), width: 1),
        boxShadow: const [
          BoxShadow(color: Color(0x28FFD600), blurRadius: 9, spreadRadius: 1),
          BoxShadow(color: Colors.black54, blurRadius: 4, offset: Offset(0, 3)),
        ],
        borderRadius: BorderRadius.circular(size * 0.28),
      ),
      alignment: Alignment.center,
      child: Icon(icon, size: iconSize, color: iconColor,
          shadows: const [Shadow(color: Color(0x70FFD600), blurRadius: 6)]),
    );
  }
}
